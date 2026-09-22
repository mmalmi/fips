//! Rediscovery after genuine link death distinguishes admitted application use
//! from link maintenance. Neither case installs a source binding or a peer roster.
use super::*;
use crate::node::EndpointDataIo;
use crate::node::tests::session::{run_large_stack_async_test, send_endpoint_data_via_dataplane};
use futures::FutureExt;
use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;

const S: usize = 0;
const A: usize = 1;
const I: usize = 2;
const D: usize = 3;
const R: usize = 4;
const NAMES: [&str; 5] = ["source", "boundary", "refill", "stranger", "returning"];
const BEFORE: &[u8] = b"one actual end-to-end payload through the returning neighbor";
const AFTER: &[u8] = b"one original payload after automatic rediscovery";

type Owner = (LinkId, Option<SessionIndex>, Option<SessionIndex>, u64);

#[test]
fn recently_lost_transit_neighbor_precedes_ordinary_discovery() {
    run(Some((S, R)));
}

#[test]
fn heartbeat_only_lost_neighbor_keeps_ordinary_discovery_order() {
    run(None);
}

#[test]
fn recently_lost_local_sender_neighbor_precedes_ordinary_discovery() {
    run(Some((A, R)));
}

#[test]
fn recently_lost_local_receiver_neighbor_precedes_ordinary_discovery() {
    run(Some((R, A)));
}

fn run(before: Option<(usize, usize)>) {
    run_large_stack_async_test("discovered-neighbor-reconnection", move || async move {
        let _guard = spanning_tree::lock_large_network_test().await;
        let name = format!(
            "discovered-neighbor-reconnection-{}-{before:?}",
            std::process::id()
        );
        let network = SimNetwork::new(107);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut identities: Vec<_> = (1..=5)
            .map(|byte| Identity::from_secret_bytes(&[byte; 32]).unwrap())
            .collect();
        // Fixed public test scalars, sorted only to make D precede R in A's
        // discovery order. No seed search, outcome-dependent choice, or cursor mutation.
        let mut nodes = Vec::new();
        for (index, identity) in identities.iter().enumerate().take(I) {
            nodes.push(make_node(&name, index, identity).await);
        }
        identities[I..=R]
            .sort_by_key(|identity| nodes[A].node.neighbor_rotation_order(*identity.node_addr()));
        for (index, identity) in identities.iter().enumerate().skip(I) {
            nodes.push(make_node(&name, index, identity).await);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, &network, before))
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
    config.node.system_files_enabled = false;
    config.node.identity.nsec = Some(crate::encode_nsec(&identity.keypair().secret_key()));
    config.node.identity.persistent = false;
    config.node.limits.max_peers = if index == A { 2 } else { 1 };
    config.node.limits.max_connections = 1;
    config.node.limits.max_links = if index == A { 3 } else { 1 };
    config.node.heartbeat_interval_secs = 1;
    config.node.link_dead_timeout_secs = 3;
    config.node.fast_link_dead_timeout_secs = 3;
    config.node.rate_limit.handshake_timeout_secs = 6;
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

fn owner(nodes: &[TestNode], local: usize, remote: usize) -> Owner {
    let peer = nodes[local]
        .node
        .get_peer(nodes[remote].node.node_addr())
        .expect("real authenticated owner must remain present");
    (
        peer.link_id(),
        peer.our_index(),
        peer.their_index(),
        peer.session_generation(),
    )
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

fn caps(nodes: &[TestNode]) {
    for (index, node) in nodes.iter().enumerate() {
        let peers = if index == A { 2 } else { 1 };
        let links = if index == A { 3 } else { 1 };
        assert!(node.node.config.peers.is_empty());
        assert!(node.node.peer_count() <= peers, "peer cap at {index}");
        assert!(
            node.node.connection_count() <= 1,
            "candidate cap at {index}"
        );
        assert!(node.node.link_count() <= links, "link cap at {index}");
        assert!(
            node.node.index_allocator.count() <= links,
            "index cap at {index}"
        );
        assert!(node.node.pending_connects.is_empty());
    }
}

async fn authenticate(nodes: &mut [TestNode], remote: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        process_available_packets(nodes).await;
        caps(nodes);
        if reciprocal(nodes, A, remote) && nodes[A].node.connection_count() == 0 {
            return;
        }
        assert!(Instant::now() < deadline, "real discovery authentication");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

struct Traffic {
    io: Vec<EndpointDataIo>,
    local_owner: [Owner; 2],
    offered: u32,
    received: BTreeSet<u32>,
    before_received: bool,
    before: Option<(usize, usize)>,
    after_peer: Option<usize>,
    after_received: bool,
    next_payload: Instant,
    next_tick: Instant,
}

impl Traffic {
    fn new(nodes: &mut [TestNode], before: Option<(usize, usize)>) -> Self {
        let local_owner = [owner(nodes, S, A), owner(nodes, A, S)];
        let io = nodes
            .iter_mut()
            .map(|node| node.node.attach_endpoint_data_io(32).unwrap())
            .collect();
        Self {
            io,
            local_owner,
            offered: 0,
            received: BTreeSet::new(),
            before_received: false,
            before,
            after_peer: None,
            after_received: false,
            next_payload: Instant::now(),
            next_tick: Instant::now(),
        }
    }

    async fn turn(&mut self, nodes: &mut [TestNode], offer_local: bool) {
        if offer_local && Instant::now() >= self.next_payload {
            self.next_payload = Instant::now() + Duration::from_millis(250);
            self.offered = self.offered.checked_add(1).unwrap();
            let mut payload = vec![b'L'];
            payload.extend_from_slice(&self.offered.to_be_bytes());
            let target = identity(nodes, A);
            send_endpoint_data_via_dataplane(&mut nodes[S].node, target, payload)
                .await
                .unwrap();
        }
        // Existing native maintenance, once per second. Discovery is polled at
        // each real topology exposure below so the selected pending owner can
        // be inspected before its remote processes Msg1.
        if Instant::now() >= self.next_tick {
            self.next_tick = Instant::now() + Duration::from_secs(1);
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
        assert_eq!(owner(nodes, S, A), self.local_owner[0]);
        assert_eq!(owner(nodes, A, S), self.local_owner[1]);
        for (index, io) in self.io.iter_mut().enumerate() {
            loop {
                let event = match io.event_rx.try_recv() {
                    Ok(event) => event,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(error) => panic!("endpoint receiver closed: {error}"),
                };
                io.event_rx.release_messages(event.message_count());
                for message in event.messages {
                    let payload = message.payload.as_slice();
                    if payload == BEFORE {
                        let (source, destination) = self.before.expect("initial application flow");
                        assert_eq!(index, destination);
                        assert_eq!(
                            message.source_peer.node_addr(),
                            nodes[source].node.node_addr()
                        );
                        assert!(!self.before_received, "duplicate initial original");
                        self.before_received = true;
                        continue;
                    }
                    assert_eq!(message.source_peer.node_addr(), nodes[S].node.node_addr());
                    if index == A {
                        assert_eq!(payload.len(), 5);
                        assert_eq!(payload[0], b'L');
                        let sequence = u32::from_be_bytes(payload[1..].try_into().unwrap());
                        assert!(sequence > 0 && sequence <= self.offered);
                        assert!(self.received.insert(sequence), "duplicate local original");
                    } else {
                        assert_eq!(payload, AFTER);
                        assert_eq!(Some(index), self.after_peer);
                        assert!(!self.after_received, "duplicate recovered routed original");
                        self.after_received = true;
                    }
                }
            }
        }
    }
}

async fn wait_for(
    nodes: &mut [TestNode],
    traffic: &mut Traffic,
    seconds: u64,
    context: &str,
    done: impl Fn(&[TestNode], &Traffic) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        traffic.turn(nodes, true).await;
        if done(nodes, traffic) {
            return;
        }
        if Instant::now() >= deadline {
            snapshot(nodes, traffic, context);
            panic!("{context}");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, before: Option<(usize, usize)>) {
    network.set_link(NAMES[A], NAMES[S], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    authenticate(nodes, S).await;
    network.set_link(NAMES[A], NAMES[R], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    authenticate(nodes, R).await;
    let returning = *nodes[R].node.node_addr();
    let stranger = *nodes[D].node.node_addr();
    let original = owner(nodes, A, R);
    let mut traffic = Traffic::new(nodes, before);
    // All cases include real heartbeats and useful internal traffic. Only
    // application cases send the additional original across the returning link.
    let heartbeat_until = Instant::now() + Duration::from_millis(1_150);
    wait_for(
        nodes,
        &mut traffic,
        4,
        "warm live heartbeats",
        |_, traffic| Instant::now() >= heartbeat_until && !traffic.received.is_empty(),
    )
    .await;
    assert!(
        nodes[A]
            .node
            .dataplane_fmp_link_metrics(&returning, Instant::now())
            .unwrap()
            .current_epoch_authenticated
    );
    if let Some((source, destination)) = before {
        let target = identity(nodes, destination);
        send_endpoint_data_via_dataplane(&mut nodes[source].node, target, BEFORE.to_vec())
            .await
            .unwrap();
        wait_for(
            nodes,
            &mut traffic,
            15,
            "original application payload over the returning link",
            |_, traffic| traffic.before_received,
        )
        .await;
    }
    assert_eq!(
        nodes[A]
            .node
            .get_peer(&returning)
            .unwrap()
            .has_recent_transit_demand(Node::now_ms(), 1_000),
        before == Some((S, R))
    );
    assert_eq!(
        nodes[A].node.sessions.contains_key(&returning),
        matches!(before, Some((A, R) | (R, A)))
    );
    assert!(nodes[A].node.source_routes.is_empty());
    assert!(
        !nodes[A]
            .node
            .pending_session_traffic
            .has_traffic_for(&returning)
    );

    // Only the physical link changes. Heartbeat maintenance, not explicit
    // Disconnect or direct peer removal, retires both real authenticated owners.
    network.set_link_up(NAMES[A], NAMES[R], false);
    wait_for(
        nodes,
        &mut traffic,
        6,
        "physical loss must reap both owners",
        |nodes, _| {
            nodes[A].node.get_peer(nodes[R].node.node_addr()).is_none()
                && nodes[R].node.get_peer(nodes[A].node.node_addr()).is_none()
        },
    )
    .await;
    assert!(nodes[A].node.get_link(&original.0).is_none());
    assert!(
        !nodes[A]
            .node
            .index_allocator
            .is_allocated(original.1.unwrap())
    );
    assert_eq!(nodes[A].node.peer_count(), 1);
    assert_eq!(nodes[A].node.connection_count(), 0);

    network.set_link(NAMES[A], NAMES[I], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    wait_for(
        nodes,
        &mut traffic,
        4,
        "ordinary discovery refills roster",
        |nodes, _| reciprocal(nodes, A, I) && nodes[A].node.connection_count() == 0,
    )
    .await;
    let refill = owner(nodes, A, I);
    let admitted = nodes[A]
        .node
        .get_peer(nodes[I].node.node_addr())
        .unwrap()
        .authenticated_at();
    wait_for(
        nodes,
        &mut traffic,
        3,
        "refill reaches its real minimum age",
        |_, _| Node::now_ms().saturating_sub(admitted) >= 1_100,
    )
    .await;
    assert_eq!(nodes[A].node.peer_count(), 2);
    assert!(
        nodes[A]
            .node
            .has_neighbor_rotation_opportunity(Node::now_ms())
    );
    assert!(nodes[A].node.peer_has_application_demand(
        nodes[S].node.node_addr(),
        Node::now_ms(),
        1_000
    ));
    assert!(!nodes[A].node.peer_has_queued_application_demand(&returning));
    assert!(
        nodes[A].node.neighbor_rotation_order(stranger)
            < nodes[A].node.neighbor_rotation_order(returning)
    );

    network.set_link_up(NAMES[A], NAMES[R], true);
    network.set_link(NAMES[A], NAMES[D], SimLink::default());
    let advertised = nodes[A].node.transports[&nodes[A].transport_id]
        .discover()
        .unwrap();
    for remote in [D, R] {
        assert!(
            advertised
                .iter()
                .any(|hint| hint.pubkey_hint == Some(nodes[remote].node.identity().pubkey()))
        );
    }
    nodes[A].node.poll_transport_discovery().await;
    assert_eq!(nodes[A].node.connection_count(), 1);
    let candidate = nodes[A].node.peers.connection_values().next().unwrap();
    assert!(candidate.is_outbound() && !candidate.has_session());
    let expected = if before.is_some() { R } else { D };
    assert_eq!(
        candidate.expected_identity().unwrap().node_addr(),
        nodes[expected].node.node_addr(),
        "before={before:?}: admitted application use must select the returning peer ahead of an earlier ordinary stranger; heartbeat history must not"
    );
    assert_eq!(owner(nodes, A, I), refill, "discovery alone cannot evict");
    caps(nodes);
    wait_for(
        nodes,
        &mut traffic,
        5,
        "fresh discovery proof must authenticate",
        |nodes, _| reciprocal(nodes, A, expected) && nodes[A].node.connection_count() == 0,
    )
    .await;
    assert!(nodes[A].node.get_peer(nodes[I].node.node_addr()).is_none());
    assert_eq!(owner(nodes, A, S), traffic.local_owner[1]);
    traffic.after_peer = Some(expected);
    let target = identity(nodes, expected);
    send_endpoint_data_via_dataplane(&mut nodes[S].node, target, AFTER.to_vec())
        .await
        .unwrap();
    wait_for(
        nodes,
        &mut traffic,
        15,
        "new routed payload after rediscovery",
        |_, traffic| traffic.after_received,
    )
    .await;
    let drain_deadline = Instant::now() + Duration::from_secs(3);
    while traffic.received.len() != traffic.offered as usize {
        traffic.turn(nodes, false).await;
        assert!(
            Instant::now() < drain_deadline,
            "all original internal payloads must arrive once"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(traffic.before_received, before.is_some());
    assert!(traffic.after_received);
    caps(nodes);
}

fn label(nodes: &[TestNode], address: &NodeAddr) -> &'static str {
    nodes
        .iter()
        .position(|node| node.node.node_addr() == address)
        .map_or("unknown", |index| NAMES[index])
}

// Pure observations: find_next_hop would change route/cache selection. Report
// the installed and last-used carrier without changing future routing decisions.
fn snapshot(nodes: &[TestNode], traffic: &Traffic, phase: &str) {
    let remote = traffic.after_peer.unwrap_or(R);
    let records: Vec<_> = [S, A, remote].into_iter().map(|index| {
        let node = &nodes[index].node;
        let target = nodes[if index == remote { S } else { remote }].node.node_addr();
        let peers: Vec<_> = node.peers.values().map(|peer| serde_json::json!({
            "peer":label(nodes,peer.node_addr()),"can_send":peer.can_send(),
            "healthy":peer.is_healthy(),"authenticated_ms":peer.authenticated_at(),
            "link":peer.link_id().as_u64(),"generation":peer.session_generation(),
            "our_index":peer.our_index().map(|i|i.as_u32()),
            "their_index":peer.their_index().map(|i|i.as_u32()),
            "tree_peer":node.is_tree_peer(peer.node_addr()),"may_reach_target":peer.may_reach(target),
            "metrics":node.dataplane_fmp_link_metrics(peer.node_addr(),Instant::now()).map(|m|serde_json::json!({
                "current_authenticated":m.current_epoch_authenticated,"tx":m.tx_packets,
                "rx":m.rx_packets,"last_rx_age_ms":m.last_recv_age_ms
            }))
        })).collect();
        let session = node.get_session(target).map(|session|serde_json::json!({
            "established":session.is_established(),"created_ms":session.created_at(),
            "started_ms":session.session_start_ms()
        }));
        let lookup = node.pending_lookups.get(target).map(|lookup|serde_json::json!({
            "attempt":lookup.attempt,"initiated_ms":lookup.initiated_ms,
            "last_sent_ms":lookup.last_sent_ms,"awaiting_first_request":lookup.awaiting_first_request()
        }));
        let activity = node.dataplane.fsp_owner_activity(target).map(|activity|serde_json::json!({
            "last_outbound_next_hop":activity.last_outbound_next_hop().map(|p|label(nodes,&p)),
            "traffic_packets_sent_recv_bytes_sent_recv":activity.traffic_counters()
        }));
        serde_json::json!({
            "node":NAMES[index],"target":label(nodes,target),"now_ms":Node::now_ms(),
            "root":label(nodes,node.tree_state.root()),"peers":peers,
            "binding":node.source_routes.get(target).map(|p|label(nodes,p)),
            "installed_fsp_next_hop":node.dataplane.fsp_owner_next_hop(target).map(|p|label(nodes,&p)),
            "application_route_ready":node.dataplane_application_route_ready(target),
            "coords_root":node.coord_cache.get(target,Node::now_ms()).map(|c|label(nodes,c.root_id())),
            "session":session,"activity":activity,"lookup":lookup,
            "queued_target":node.pending_session_traffic.endpoint_data_for(target).map_or(0,|q|q.len()),
            "forwarding":node.stats().forwarding.snapshot(),"discovery":node.stats().discovery.snapshot()
        })
    }).collect();
    eprintln!(
        "reconnection state: {}",
        serde_json::json!({
            "phase":phase,"local_offered":traffic.offered,"local_received":traffic.received.len(),
            "before_received":traffic.before_received,"after_received":traffic.after_received,"nodes":records
        })
    );
}
