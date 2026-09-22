//! A queued final destination can name a previously authenticated carrier.
//! Binding is established before real departure, never synthesized afterward.
//! Natural Tree routing and real discovery provide every coordinate; no cache
//! injection or alternate routing mode masks convergence in either case.
use super::*;
use crate::node::EndpointDataIo;
use crate::node::tests::session::{run_large_stack_async_test, send_endpoint_data_via_dataplane};
use crate::protocol::{Disconnect, DisconnectReason};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const A: usize = 0;
const I: usize = 1;
const B: usize = 2;
const C: usize = 3;
const R: usize = 4;
const D: usize = 5;
const NAMES: [&str; 6] = ["a", "idle", "b", "c", "relay", "destination"];
const BEFORE: &[u8] = b"real routed session before carrier departure";
const ORIGINAL: &[u8] = b"one original for D through its retained relay R";

#[test]
fn retained_carrier_precedes_earlier_candidates_for_queued_endpoint() {
    run(Case::Priority);
}

#[test]
fn measure_retained_carrier_queued_delivery_with_three_candidate_admissions() {
    run(Case::Measure);
}

#[test]
fn delivered_one_way_traffic_preserves_authenticated_carrier_during_discovery() {
    run(Case::OneWay);
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Priority,
    Measure,
    OneWay,
}

fn run(case: Case) {
    run_large_stack_async_test("retained-carrier-demand", move || async move {
        let _guard = spanning_tree::lock_large_network_test().await;
        let name = format!("retained-carrier-demand-{}-{case:?}", std::process::id());
        let network = SimNetwork::new(103);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut identities: Vec<_> = (1..=6)
            .map(|byte| Identity::from_secret_bytes(&[byte; 32]).unwrap())
            .collect();
        // Ordinary fixed test scalars, with role ordering only: the still
        // advertised I precedes B/C/R in A's discovery order, so it cannot change
        // the comparison. No seed search or identity selected from test outcomes.
        let mut nodes = vec![make_node(&name, A, &identities[A]).await];
        identities[I..=R]
            .sort_by_key(|identity| nodes[A].node.neighbor_rotation_order(*identity.node_addr()));
        for (index, identity) in identities.iter().enumerate().skip(I) {
            nodes.push(make_node(&name, index, identity).await);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, &network, case))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn make_node(network: &str, index: usize, identity: &Identity) -> TestNode {
    let mut config = Config::new();
    assert_eq!(config.node.routing.mode, crate::config::RoutingMode::Tree);
    config.node.system_files_enabled = false;
    config.node.identity.nsec = Some(crate::encode_nsec(&identity.keypair().secret_key()));
    config.node.identity.persistent = false;
    config.node.rekey.enabled = false;
    config.node.limits.max_peers = if index == R { 2 } else { 1 };
    config.node.limits.max_connections = 1;
    config.node.limits.max_links = match index {
        A => 2,
        R => 3,
        _ => 1,
    };
    config.node.rate_limit.handshake_timeout_secs = 3;
    if index == A {
        config.node.neighbor_rotation = Some(NeighborRotationConfig {
            idle_secs: 1,
            interval_secs: 1,
        });
    }
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network.to_string()),
        addr: Some(NAMES[index].to_string()),
        auto_connect: Some(index == A),
        ..Default::default()
    });
    configured_discovering_node(config, NAMES[index]).await
}

fn identity(nodes: &[TestNode], index: usize) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(nodes[index].node.identity().pubkey_full())
}

fn caps(nodes: &[TestNode]) {
    for (index, node) in nodes.iter().enumerate() {
        assert!(
            node.node.config.peers.is_empty(),
            "no configured identity roster"
        );
        assert!(node.node.peer_count() <= if index == R { 2 } else { 1 });
        assert!(node.node.connection_count() <= 1);
        let links = match index {
            A => 2,
            R => 3,
            _ => 1,
        };
        assert!(node.node.link_count() <= links);
        assert!(
            node.node.pending_connects.is_empty(),
            "Sim uses no carrier preparations"
        );
    }
}

fn reciprocal(nodes: &[TestNode], left: usize, right: usize) -> bool {
    let Some(a) = nodes[left].node.get_peer(nodes[right].node.node_addr()) else {
        return false;
    };
    let Some(b) = nodes[right].node.get_peer(nodes[left].node.node_addr()) else {
        return false;
    };
    a.our_index() == b.their_index() && a.their_index() == b.our_index()
}

async fn authenticate_pair(nodes: &mut [TestNode], left: usize, right: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !reciprocal(nodes, left, right) {
        process_available_packets(nodes).await;
        caps(nodes);
        assert!(
            Instant::now() < deadline,
            "genuine reciprocal native authentication"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Same ordinary one-second maintenance as the direct-demand fixture, including
/// real lookup/Bloom/session work. No extra flush or synthetic cache repair.
async fn turn(nodes: &mut [TestNode], tick: &mut Instant) {
    if Instant::now() >= *tick {
        *tick = Instant::now() + Duration::from_secs(1);
        for node in nodes.iter_mut() {
            node.node.check_timeouts().await;
            node.node.check_link_heartbeats().await;
            let now = Node::now_ms();
            node.node.resend_pending_handshakes(now).await;
            node.node.resend_pending_rekeys(now).await;
            node.node.resend_pending_session_handshakes(now).await;
            node.node.resend_pending_session_msg3(now).await;
            node.node.retry_pending_session_traffic().await;
            node.node.check_mmp_reports().await;
            node.node.check_session_mmp_reports().await;
            node.node.check_rekey().await;
            node.node.check_session_rekey().await;
            node.node.check_pending_lookups(now).await;
            node.node.poll_pending_connects().await;
            node.node.process_pending_retries(now).await;
            node.node.check_tree_state().await;
            node.node.send_pending_tree_announces().await;
            node.node.check_bloom_state().await;
        }
    }
    process_available_packets(nodes).await;
    caps(nodes);
}

fn received(receiver: &mut EndpointDataIo, source: &NodeAddr, expected: &[u8]) -> bool {
    match receiver.event_rx.try_recv() {
        Ok(event) => {
            let count = event.message_count();
            assert_eq!(count, 1, "only the single original is offered");
            for message in event.messages {
                assert_eq!(message.source_peer.node_addr(), source);
                assert_eq!(message.payload.as_slice(), expected);
            }
            receiver.event_rx.release_messages(count);
            true
        }
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => false,
        Err(error) => panic!("endpoint receiver closed: {error}"),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SessionWitness {
    hash: [u8; 32],
    created: u64,
    started: u64,
}

fn session(node: &Node, destination: &NodeAddr) -> SessionWitness {
    let entry = node
        .get_session(destination)
        .expect("retain original independent FSP");
    assert!(entry.is_established());
    assert!(node.dataplane_has_fsp_owner(destination));
    SessionWitness {
        hash: *entry.handshake_hash().unwrap(),
        created: entry.created_at(),
        started: entry.session_start_ms(),
    }
}

fn retained(nodes: &[TestNode], witnesses: &[SessionWitness; 2]) {
    let source = nodes[A].node.node_addr();
    let destination = nodes[D].node.node_addr();
    assert_eq!(
        nodes[A].node.source_routes.get(destination),
        Some(nodes[R].node.node_addr()),
        "the only binding was installed before departure"
    );
    assert_eq!(session(&nodes[A].node, destination), witnesses[0]);
    assert_eq!(session(&nodes[D].node, source), witnesses[1]);
    assert!(
        reciprocal(nodes, R, D),
        "downstream adjacency must stay intact"
    );
}

fn queued(node: &Node, target: &NodeAddr) -> usize {
    node.pending_session_traffic
        .endpoint_data_for(target)
        .map_or(0, |queue| queue.len())
}

fn selected(nodes: &[TestNode]) -> (NodeAddr, LinkId) {
    assert_eq!(nodes[A].node.connection_count(), 1);
    let connection = nodes[A].node.peers.connection_values().next().unwrap();
    assert!(connection.is_outbound());
    (
        *connection.expected_identity().unwrap().node_addr(),
        connection.link_id(),
    )
}

fn label(nodes: &[TestNode], address: &NodeAddr) -> &'static str {
    nodes
        .iter()
        .position(|node| node.node.node_addr() == address)
        .map_or("unknown", |i| NAMES[i])
}

// Read-only, bounded observations at selection, admissions and deadline. These
// queries do not run maintenance, refresh routes or touch cache recency.
fn snapshot(
    nodes: &[TestNode],
    phase: &str,
    offered: Instant,
    attempts: &[&str],
    admissions: usize,
) {
    let destination = nodes[D].node.node_addr();
    let records: Vec<_> = [A, R, D].into_iter().map(|index| {
        let node = &nodes[index].node;
        let target = if index == D { nodes[A].node.node_addr() } else { destination };
        let peers: Vec<_> = node.peers.values().map(|peer| serde_json::json!({
            "peer":label(nodes,peer.node_addr()),"can_send":peer.can_send(),
            "authenticated_ms":peer.authenticated_at(),"link":peer.link_id().as_u64(),
            "our_index":peer.our_index().map(|i|i.as_u32()),
            "their_index":peer.their_index().map(|i|i.as_u32()),
            "previous_index":peer.previous_our_index().map(|i|i.as_u32()),
            "pending_session":peer.pending_new_session().is_some(),
            "generation":peer.session_generation(),
            "decrypt_failures":peer.consecutive_decrypt_failures(),
            "replay_suppressed":peer.replay_suppressed_count(),
            "tree_peer":node.is_tree_peer(peer.node_addr()),"may_reach_target":peer.may_reach(target),
            "metrics":node.dataplane_fmp_link_metrics(peer.node_addr(),Instant::now()).map(|m|serde_json::json!({
                "current_authenticated":m.current_epoch_authenticated,"tx":m.tx_packets,
                "rx":m.rx_packets,"last_rx_age_ms":m.last_recv_age_ms
            }))
        })).collect();
        let lookup = node.pending_lookups.get(target).map(|lookup| serde_json::json!({
            "attempt":lookup.attempt,"initiated_ms":lookup.initiated_ms,
            "last_sent_ms":lookup.last_sent_ms,"awaiting_first_request":lookup.awaiting_first_request()
        }));
        let session = node.get_session(target).map(|session| serde_json::json!({
            "established":session.is_established(),"created_ms":session.created_at(),
            "started_ms":session.session_start_ms(),"hash":session.handshake_hash()
        }));
        serde_json::json!({"node":NAMES[index],"root":label(nodes,node.tree_state.root()),
            "peers":peers,"binding":node.source_routes.get(target).map(|p|label(nodes,p)),
            "fsp_next_hop":node.dataplane.fsp_owner_next_hop(target).map(|p|label(nodes,&p)),
            "application_route_ready":node.dataplane_application_route_ready(target),
            "coords_root":node.coord_cache.get(target,Node::now_ms()).map(|c|label(nodes,c.root_id())),
            "lookup":lookup,"session":session,"queued_target":queued(node,target),
            "queued_carrier":queued(node,nodes[R].node.node_addr()),
            "requests_initiated":node.stats().discovery.req_initiated,
            "responses_accepted":node.stats().discovery.resp_accepted,
            "discovery":node.stats().discovery.snapshot()})
    }).collect();
    eprintln!(
        "retained carrier state: {}",
        serde_json::json!({
            "phase":phase,"elapsed_ms":offered.elapsed().as_millis(),"attempts":attempts,
            "admissions":admissions,"downstream_reciprocal":reciprocal(nodes,R,D),"nodes":records
        })
    );
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, case: Case) {
    let strict = matches!(case, Case::Priority);
    network.set_link(NAMES[R], NAMES[D], SimLink::default());
    let target = identity(nodes, D);
    let relay = identity(nodes, R);
    let source = *nodes[A].node.node_addr();
    let destination = *target.node_addr();
    let remote = nodes[D].addr.clone();
    let transport = nodes[R].transport_id;
    nodes[R]
        .node
        .initiate_connection(transport, remote, target)
        .await
        .unwrap();
    authenticate_pair(nodes, R, D).await;
    network.set_link(NAMES[A], NAMES[R], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    authenticate_pair(nodes, A, R).await;
    nodes[A]
        .node
        .set_endpoint_source_route(target, Some(relay))
        .unwrap();
    let _source_io = nodes[A].node.attach_endpoint_data_io(8).unwrap();
    let mut receiver = nodes[D].node.attach_endpoint_data_io(8).unwrap();
    send_endpoint_data_via_dataplane(&mut nodes[A].node, target, BEFORE.to_vec())
        .await
        .unwrap();
    let mut tick = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !received(&mut receiver, &source, BEFORE) {
        turn(nodes, &mut tick).await;
        assert!(
            Instant::now() < deadline,
            "initial real A-to-R-to-D delivery premise"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let witnesses = [
        session(&nodes[A].node, &destination),
        session(&nodes[D].node, &source),
    ];
    assert_eq!(witnesses[0].hash, witnesses[1].hash);
    let sent_before = nodes[A]
        .node
        .dataplane
        .fsp_owner_activity(&destination)
        .unwrap()
        .traffic_counters();
    let received_before = nodes[D]
        .node
        .dataplane
        .fsp_owner_activity(&source)
        .unwrap()
        .traffic_counters();
    if matches!(case, Case::OneWay) {
        let original = [A, R].map(|index| {
            let remote = if index == A { R } else { A };
            let node = &nodes[index].node;
            let peer = node.get_peer(nodes[remote].node.node_addr()).unwrap();
            assert!(
                node.dataplane_fmp_link_metrics(peer.node_addr(), Instant::now())
                    .unwrap()
                    .current_epoch_authenticated
            );
            (
                peer.link_id(),
                peer.our_index(),
                peer.their_index(),
                peer.session_generation(),
            )
        });
        assert!(sent_before.0 > 0);
        assert_eq!(
            sent_before.1, 0,
            "valid one-way traffic has no reverse application payload"
        );
        nodes[A].node.poll_transport_discovery().await;
        assert_eq!(
            nodes[A].node.connection_count(),
            0,
            "delivered one-way traffic must not redial a fresh authenticated carrier"
        );
        turn(nodes, &mut tick).await;
        for (position, index) in [A, R].into_iter().enumerate() {
            let remote = if index == A { R } else { A };
            let peer = nodes[index]
                .node
                .get_peer(nodes[remote].node.node_addr())
                .unwrap();
            assert_eq!(
                (
                    peer.link_id(),
                    peer.our_index(),
                    peer.their_index(),
                    peer.session_generation()
                ),
                original[position]
            );
        }
        assert!(reciprocal(nodes, A, R));
        return;
    }
    let old_link = nodes[A].node.get_peer(relay.node_addr()).unwrap().link_id();
    let old_index = nodes[A]
        .node
        .get_peer(relay.node_addr())
        .unwrap()
        .our_index()
        .unwrap();

    // Both encrypted Disconnect flights precede receive processing. Removing
    // both real adjacencies avoids a stale one-sided FMP rejoin premise.
    let disconnect = Disconnect::new(DisconnectReason::Shutdown).encode();
    nodes[A]
        .node
        .send_dataplane_fmp_link_plaintext(relay.node_addr(), &disconnect, false)
        .await
        .unwrap();
    nodes[R]
        .node
        .send_dataplane_fmp_link_plaintext(&source, &disconnect, false)
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while nodes[A].node.get_peer(relay.node_addr()).is_some()
        || nodes[R].node.get_peer(&source).is_some()
    {
        process_available_packets(nodes).await;
        caps(nodes);
        assert!(
            Instant::now() < deadline,
            "actual authenticated carrier departure"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    network.set_link_up(NAMES[A], NAMES[R], false);
    assert!(nodes[A].node.get_link(&old_link).is_none());
    assert!(!nodes[A].node.index_allocator.is_allocated(old_index));
    retained(nodes, &witnesses);
    assert!(nodes[A].node.find_next_hop(&destination).is_none());
    network.set_link(NAMES[A], NAMES[I], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    authenticate_pair(nodes, A, I).await;
    let incumbent = *nodes[I].node.node_addr();
    let authenticated = nodes[A]
        .node
        .get_peer(&incumbent)
        .unwrap()
        .authenticated_at();
    while Node::now_ms().saturating_sub(authenticated) < 1_050 {
        turn(nodes, &mut tick).await;
        retained(nodes, &witnesses);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        nodes[A]
            .node
            .has_neighbor_rotation_opportunity(Node::now_ms())
    );
    let offered = Instant::now();
    send_endpoint_data_via_dataplane(&mut nodes[A].node, target, ORIGINAL.to_vec())
        .await
        .unwrap();
    assert_eq!(queued(&nodes[A].node, &destination), 1);
    assert_eq!(queued(&nodes[A].node, relay.node_addr()), 0);
    assert!(
        !nodes[A]
            .node
            .pending_session_traffic
            .has_traffic_for(relay.node_addr())
    );
    retained(nodes, &witnesses);
    let cursor = nodes[A]
        .node
        .neighbor_rotation_order(*nodes[B].node.node_addr());
    assert!(
        cursor
            < nodes[A]
                .node
                .neighbor_rotation_order(*nodes[C].node.node_addr())
    );
    assert!(
        nodes[A]
            .node
            .neighbor_rotation_order(*nodes[C].node.node_addr())
            < nodes[A].node.neighbor_rotation_order(*relay.node_addr())
    );
    for candidate in [B, C, R] {
        network.set_link(NAMES[A], NAMES[candidate], SimLink::default());
    }
    let network_before = network.stats();
    nodes[A].node.poll_transport_discovery().await;
    let (first, mut last_attempt) = selected(nodes);
    eprintln!(
        "retained carrier selection: {}",
        serde_json::json!({
            "strict":strict,"selected":label(nodes,&first),"queue_destination":1,
            "queue_carrier":0,"binding_retained":true,"original_fsp_retained":true
        })
    );
    snapshot(nodes, "selected", offered, &[label(nodes, &first)], 0);
    if strict {
        assert_eq!(
            first,
            *relay.node_addr(),
            "retained carrier R must precede B/C for queued D"
        );
        assert_eq!(
            nodes[A]
                .node
                .neighbor_rotation_order(*nodes[B].node.node_addr()),
            cursor,
            "carrier demand must preserve the ordinary exploration cursor"
        );
    }
    let mut attempts = vec![label(nodes, &first)];
    let mut admissions = 0;
    let mut previous = incumbent;
    let mut next_discovery = Instant::now() + Duration::from_secs(1);
    let deadline = offered + Duration::from_secs(15);
    let delivered = loop {
        turn(nodes, &mut tick).await;
        retained(nodes, &witnesses);
        if let Some(peer) = nodes[A].node.peers.values().next()
            && *peer.node_addr() != previous
        {
            admissions += 1;
            previous = *peer.node_addr();
            snapshot(nodes, "admitted", offered, &attempts, admissions);
            assert!(
                admissions <= 3,
                "bounded B/C/R admissions, no forced departure"
            );
        }
        if received(&mut receiver, &source, ORIGINAL) {
            break Instant::now();
        }
        if Instant::now() >= deadline {
            snapshot(nodes, "deadline", offered, &attempts, admissions);
            panic!("original retained-carrier payload delivery deadline");
        }
        if Instant::now() >= next_discovery {
            next_discovery = Instant::now() + Duration::from_secs(1);
            nodes[A].node.poll_transport_discovery().await;
            if nodes[A].node.connection_count() > 0 {
                let (target, link) = selected(nodes);
                if link != last_attempt {
                    attempts.push(label(nodes, &target));
                    last_attempt = link;
                    if attempts.len() <= 8 {
                        snapshot(nodes, "attempt", offered, &attempts, admissions);
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert!(reciprocal(nodes, A, R));
    assert_eq!(queued(&nodes[A].node, &destination), 0);
    let duplicate_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < duplicate_deadline {
        turn(nodes, &mut tick).await;
        retained(nodes, &witnesses);
        assert!(
            !received(&mut receiver, &source, ORIGINAL),
            "original delivered exactly once"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let sent_after = nodes[A]
        .node
        .dataplane
        .fsp_owner_activity(&destination)
        .unwrap()
        .traffic_counters();
    let received_after = nodes[D]
        .node
        .dataplane
        .fsp_owner_activity(&source)
        .unwrap()
        .traffic_counters();
    assert!(sent_after.0 > sent_before.0 && received_after.1 > received_before.1);
    eprintln!(
        "retained carrier delivery: {}",
        serde_json::json!({
            "strict":strict,"attempts":attempts,"admissions":admissions,"offered":1,"delivered":1,
            "first_observed_ms":delivered.duration_since(offered).as_millis(),
            "duplicate_observation_ms":200,"source_counters_before":sent_before,"source_counters_after":sent_after,
            "destination_counters_before":received_before,"destination_counters_after":received_after,
            "network_delta":network.stats().delta_since(&network_before)
        })
    );
}
