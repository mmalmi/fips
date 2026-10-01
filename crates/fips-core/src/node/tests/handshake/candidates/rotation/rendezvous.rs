//! A ready bridge must get an admission opportunity beside an unanswered dial.
use super::*;
use crate::config::{SimTransportConfig, TransportInstances};
use crate::node::EndpointDataIo;
use crate::node::tests::session::{run_large_stack_async_test, send_endpoint_data_via_dataplane};
use crate::node::tests::spanning_tree::{
    lock_large_network_test, process_dataplane_completions, process_dataplane_packet,
    process_dataplane_packet_once,
};
use crate::node::wire::Msg1Header;
use crate::{SimLink, SimNetwork, register_sim_network, unregister_sim_network};
use futures::FutureExt;
use serde_json::{Value, json};
use std::panic::AssertUnwindSafe;

#[path = "rendezvous/responsive.rs"]
mod responsive;

#[path = "rendezvous/preparation.rs"]
mod preparation;

#[path = "rendezvous/same_path_rejoin.rs"]
mod same_path_rejoin;

#[path = "rendezvous/retention.rs"]
mod retention;

const ADDRESSES: [&str; 8] = [
    "a", "b", "useful-a", "useful-b", "idle-a", "idle-b", "silent-a", "silent-b",
];
const LOCAL_FLOWS: [(usize, usize); 4] = [(0, 2), (2, 0), (1, 3), (3, 1)];
const TIMEOUT_MS: u64 = 4_000;

#[test]
fn ready_bridge_gets_an_opportunity_while_other_outbound_is_unanswered() {
    run_large_stack_async_test("rotation-offset-rendezvous", || async {
        let _guard = lock_large_network_test().await;
        let name = format!("rotation-offset-rendezvous-{}", std::process::id());
        let network = SimNetwork::new(83);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        for (a, b) in [(0, 2), (0, 4), (1, 3), (1, 5)] {
            network.set_link(ADDRESSES[a], ADDRESSES[b], SimLink::default());
        }
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for (i, address) in ADDRESSES.iter().enumerate() {
            nodes.push(make_node(&name, address, i < 2).await);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, &network))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn make_node(network: &str, address: &str, boundary: bool) -> TestNode {
    make_node_with(network, address, boundary, |_| {}).await
}

async fn make_node_with(
    network: &str,
    address: &str,
    boundary: bool,
    configure: impl FnOnce(&mut Config),
) -> TestNode {
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.limits.max_peers = if boundary { 2 } else { 1 };
    config.node.limits.max_connections = 1;
    config.node.limits.max_links = if boundary { 3 } else { 2 };
    config.node.rate_limit.handshake_timeout_secs = TIMEOUT_MS / 1000;
    config.node.rate_limit.handshake_resend_interval_ms = 250;
    config.node.rate_limit.handshake_resend_backoff = 1.5;
    config.node.neighbor_rotation = boundary.then_some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network.to_owned()),
        addr: Some(address.to_owned()),
        auto_connect: Some(boundary),
        ..Default::default()
    });
    configure(&mut config);
    let mut node = Node::new(config).unwrap();
    let (packet_tx, packet_rx) = crate::transport::packet_channel(256);
    let (tun_outbound_tx, tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(256);
    node.tun_outbound_rx = Some(tun_outbound_rx);
    let mut transport = node
        .create_transports(&packet_tx)
        .await
        .into_iter()
        .find(|t| t.transport_type().name == "sim")
        .unwrap();
    let transport_id = transport.transport_id();
    transport.start().await.unwrap();
    node.transports.insert(transport_id, transport);
    TestNode {
        node,
        transport_id,
        packet_rx,
        tun_outbound_tx,
        addr: TransportAddr::from_string(address),
    }
}

fn identities(nodes: &[TestNode]) -> Vec<PeerIdentity> {
    nodes
        .iter()
        .map(|n| PeerIdentity::from_pubkey_full(n.node.identity().pubkey_full()))
        .collect()
}

async fn dial(nodes: &mut [TestNode], source: usize, destination: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[destination].node.identity().pubkey_full());
    let address = nodes[destination].addr.clone();
    let source = &mut nodes[source];
    source
        .node
        .initiate_connection(source.transport_id, address, identity)
        .await
        .unwrap();
}

#[derive(Clone, Copy)]
struct CapacityLimits {
    // Boundary nodes first, then every non-boundary node.
    connections: [usize; 2],
    links: [usize; 2],
}

impl CapacityLimits {
    const ORIGINAL: Self = Self {
        connections: [1, 1],
        links: [3, 2],
    };
}

fn caps(nodes: &[TestNode]) {
    caps_with_limits(nodes, CapacityLimits::ORIGINAL);
}

fn caps_with_limits(nodes: &[TestNode], limits: CapacityLimits) {
    for (i, n) in nodes.iter().enumerate() {
        let peers = if i < 2 { 2 } else { 1 };
        let role = usize::from(i >= 2);
        assert!(n.node.peer_count() <= peers, "hard peer cap at {i}");
        assert!(
            n.node.connection_count() <= limits.connections[role],
            "hard pending cap at {i}"
        );
        assert!(
            n.node.link_count() <= limits.links[role],
            "hard link cap at {i}"
        );
        let (owned, evidence) = index_owners(nodes, i);
        let allocated = owned
            .iter()
            .all(|index| n.node.index_allocator.is_allocated(*index));
        if !allocated || n.node.index_allocator.count() != owned.len() {
            eprintln!("rendezvous index ownership mismatch at {i}: {evidence}");
        }
        assert!(
            allocated,
            "every retained receive epoch must be allocated at {i}"
        );
        assert_eq!(
            n.node.index_allocator.count(),
            owned.len(),
            "every allocated index must have an exact active or pending owner at {i}"
        );
        assert!(n.node.config.peers.is_empty());
    }
}

fn index_owners(nodes: &[TestNode], at: usize) -> (std::collections::HashSet<SessionIndex>, Value) {
    let node = &nodes[at].node;
    let mut owned = std::collections::HashSet::new();
    let mut entries = Vec::new();
    let mut record =
        |index: Option<SessionIndex>, role: &str, peer: Option<usize>, link: LinkId| {
            if let Some(index) = index {
                owned.insert(index);
                entries.push(
                    json!({"index":index.as_u32(),"role":role,"node":peer,"link":link.as_u64()}),
                );
            }
        };
    for peer in node.peers.values() {
        let label = nodes
            .iter()
            .position(|n| n.node.node_addr() == peer.node_addr());
        record(peer.our_index(), "current", label, peer.link_id());
        record(
            peer.pending_our_index(),
            "pending_epoch",
            label,
            peer.link_id(),
        );
        record(
            peer.previous_our_index(),
            "draining_epoch",
            label,
            peer.link_id(),
        );
        record(
            peer.rekey_our_index(),
            "rekey_handshake",
            label,
            peer.link_id(),
        );
    }
    for connection in node.peers.connection_values() {
        let label = connection.expected_identity().and_then(|id| {
            nodes
                .iter()
                .position(|n| n.node.node_addr() == id.node_addr())
        });
        record(
            connection.our_index(),
            "candidate_handshake",
            label,
            connection.link_id(),
        );
    }
    let evidence =
        json!({"allocated":node.index_allocator.count(),"owned":owned.len(),"entries":entries});
    (owned, evidence)
}

async fn turn(nodes: &mut [TestNode]) {
    // The two silent endpoints retain live registered transports, but deliberately
    // do not answer their real incoming Noise packets. No link is removed.
    for n in &mut nodes[..6] {
        n.node.check_timeouts().await;
        n.node.resend_pending_handshakes(Node::now_ms()).await;
        n.node.check_mmp_reports().await;
        n.node.check_session_mmp_reports().await;
        n.node.send_pending_tree_announces().await;
        n.node
            .resend_pending_session_handshakes(Node::now_ms())
            .await;
        n.node.resend_pending_session_msg3(Node::now_ms()).await;
    }
    for n in &mut nodes[..6] {
        for _ in 0..256 {
            let Ok(packet) = n.packet_rx.try_recv() else {
                break;
            };
            process_dataplane_packet_once(&mut n.node, packet).await;
        }
        process_dataplane_completions(&mut n.node).await;
    }
    caps(nodes);
}

async fn local_round(
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: u8,
    flows: &[(usize, usize)],
) {
    send_round(nodes, ids, sequence, flows).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received = Vec::new();
    loop {
        turn(nodes).await;
        receive_round(endpoints, ids, sequence, flows, &mut received);
        if received.len() == flows.len() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "useful direct payloads must keep progressing"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn send_round(
    nodes: &mut [TestNode],
    ids: &[PeerIdentity],
    sequence: u8,
    flows: &[(usize, usize)],
) {
    send_round_with_tag(nodes, ids, &[sequence], flows).await;
}

async fn send_round_with_tag(
    nodes: &mut [TestNode],
    ids: &[PeerIdentity],
    tag: &[u8],
    flows: &[(usize, usize)],
) {
    for &(source, destination) in flows {
        let mut payload = tag.to_vec();
        payload.extend([source as u8, destination as u8]);
        send_endpoint_data_via_dataplane(&mut nodes[source].node, ids[destination], payload)
            .await
            .unwrap();
    }
}

fn receive_round(
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: u8,
    flows: &[(usize, usize)],
    received: &mut Vec<(usize, usize)>,
) {
    receive_round_with_tag(endpoints, ids, &[sequence], flows, received);
}

fn receive_round_with_tag(
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    tag: &[u8],
    flows: &[(usize, usize)],
    received: &mut Vec<(usize, usize)>,
) {
    receive_round_with_tag_and_observer(endpoints, ids, tag, flows, received, |_, _, _| false);
}

fn receive_round_with_tag_and_observer(
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    tag: &[u8],
    flows: &[(usize, usize)],
    received: &mut Vec<(usize, usize)>,
    mut observe: impl FnMut(usize, &PeerIdentity, &[u8]) -> bool,
) {
    for (destination, endpoint) in endpoints.iter_mut().enumerate() {
        while let Ok(event) = endpoint.event_rx.try_recv() {
            let count = event.message_count();
            for message in event.messages {
                let payload = message.payload.as_slice();
                if observe(destination, &message.source_peer, payload) {
                    continue;
                }
                assert_eq!(payload.len(), tag.len() + 2);
                assert_eq!(
                    &payload[..tag.len()],
                    tag,
                    "late packet from a prior observation turn"
                );
                let source = usize::from(payload[tag.len()]);
                assert_eq!(usize::from(payload[tag.len() + 1]), destination);
                assert_eq!(message.source_peer.node_addr(), ids[source].node_addr());
                assert!(flows.contains(&(source, destination)));
                assert!(
                    !received.contains(&(source, destination)),
                    "no retry or duplicate can supply progress"
                );
                received.push((source, destination));
            }
            endpoint.event_rx.release_messages(count);
        }
    }
}

fn label(ids: &[PeerIdentity], address: &NodeAddr) -> usize {
    ids.iter().position(|id| id.node_addr() == address).unwrap()
}

fn snapshot(nodes: &[TestNode], ids: &[PeerIdentity], started: tokio::time::Instant, phase: &str) {
    let before = started.elapsed().as_millis();
    let now = Node::now_ms();
    let boundaries: Vec<_> = (0..2).map(|i| {
        let n = &nodes[i].node;
        let demand_window = n.config.node.neighbor_rotation.as_ref()
            .map_or(1000, |config| config.idle_secs.saturating_mul(1000));
        let peers: Vec<_> = n.peers.iter().map(|(address, p)| json!({
            "node":label(ids,address), "link":p.link_id().as_u64(), "index":p.our_index().map(|i| i.as_u32()),
            "age_ms":now.saturating_sub(p.authenticated_at()),
            "application_demand":n.peer_has_application_demand(address,now,demand_window),
            "transit_demand":p.has_recent_transit_demand(now,demand_window),
            "pending_owner":n.peers.connection_values().any(|c| c.expected_identity().is_some_and(|id| id.node_addr()==address))
        })).collect();
        let owners: Vec<_> = n.peers.connection_values().map(|c| json!({
            "node":c.expected_identity().map(|id|label(ids,id.node_addr())), "link":c.link_id().as_u64(),
            "index":c.our_index().map(|i|i.as_u32()), "outbound":c.is_outbound(),
            "state":format!("{:?}",c.handshake_state()), "has_session":c.has_session(),
            "started_ms":c.started_at(), "age_ms":c.duration(now), "idle_ms":c.idle_time(now),
            "rotation_age_ms":c.expected_identity().and_then(|id| n.neighbor_rotation_started_at(id.node_addr()))
                .map(|started|now.saturating_sub(started))
        })).collect();
        json!({"node":i,"peers":peers,"owners":owners,"links":n.link_count(),"indexes":n.index_allocator.count(),
            "index_owners":index_owners(nodes,i).1,
            "incoming_bridge_allowed":n.can_receive_neighbor_rotation(ids[1-i].node_addr(),now),
            "outgoing_bridge_allowed":n.can_attempt_neighbor_rotation(ids[1-i].node_addr(),true,now),
            "bridge_awaits_confirmation":n.neighbor_rotation_awaits_confirmation(ids[1-i].node_addr()),
            "discovery_victim":n.discovery_rotation_victim(now).map(|addr|label(ids,&addr)),
            "bridge_order_wraps":n.neighbor_rotation_order(*ids[1-i].node_addr()).0})
    }).collect();
    let value: Value = json!({"phase":phase,"observation_ms":[before,started.elapsed().as_millis()],"boundaries":boundaries});
    eprintln!("rotation rendezvous: {value}");
}

// Rekey changes receive indices and crypto generations, not the admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetainedNeighbor {
    link: LinkId,
    authenticated_at: u64,
    remote_epoch: Option<[u8; 8]>,
}

fn original_owner(nodes: &[TestNode], ids: &[PeerIdentity], boundary: usize) -> RetainedNeighbor {
    let p = nodes[boundary]
        .node
        .get_peer(ids[boundary + 2].node_addr())
        .unwrap();
    RetainedNeighbor {
        link: p.link_id(),
        authenticated_at: p.authenticated_at(),
        remote_epoch: p.remote_epoch(),
    }
}

fn useful_retained(nodes: &[TestNode], ids: &[PeerIdentity], original: &[RetainedNeighbor]) {
    for i in 0..2 {
        assert_eq!(original_owner(nodes, ids, i), original[i]);
        let idle_ms = nodes[i]
            .node
            .config
            .node
            .neighbor_rotation
            .as_ref()
            .unwrap()
            .idle_secs
            .saturating_mul(1000);
        assert!(nodes[i].node.peer_has_application_demand(
            ids[i + 2].node_addr(),
            Node::now_ms(),
            idle_ms
        ));
    }
}

fn reciprocal_bridge(nodes: &[TestNode], ids: &[PeerIdentity]) -> bool {
    let Some(a) = nodes[0].node.get_peer(ids[1].node_addr()) else {
        return false;
    };
    let Some(b) = nodes[1].node.get_peer(ids[0].node_addr()) else {
        return false;
    };
    a.can_send()
        && b.can_send()
        && a.our_index() == b.their_index()
        && a.their_index() == b.our_index()
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork) {
    let ids = identities(nodes);
    for (a, b) in [(0, 2), (0, 4), (1, 3), (1, 5)] {
        dial(nodes, a, b).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            turn(nodes).await;
            if nodes[a].node.get_peer(ids[b].node_addr()).is_some()
                && nodes[b].node.get_peer(ids[a].node_addr()).is_some()
                && nodes[a].node.connection_count() == 0
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "real incumbent handshake must finish"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    let original: Vec<_> = (0..2).map(|i| original_owner(nodes, &ids, i)).collect();
    let started = tokio::time::Instant::now();
    let mut sequence = 0u8;
    // Age the actual idle incumbents while refreshing useful data demand.
    while started.elapsed() < Duration::from_millis(1100) {
        local_round(nodes, &mut endpoints, &ids, sequence, &LOCAL_FLOWS).await;
        sequence += 1;
        useful_retained(nodes, &ids, &original);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for i in 0..2 {
        assert_eq!(nodes[i].node.peer_count(), 2);
        assert_eq!(
            nodes[i].node.discovery_rotation_victim(Node::now_ms()),
            Some(*ids[i + 4].node_addr())
        );
    }

    network.set_link(ADDRESSES[0], ADDRESSES[6], SimLink::default());
    nodes[0].node.poll_transport_discovery().await;
    let a_candidate = nodes[0].node.peers.connection_values().next().unwrap();
    assert_eq!(
        a_candidate.expected_identity().unwrap().node_addr(),
        ids[6].node_addr()
    );
    let a_link = a_candidate.link_id();
    let a_index = a_candidate.our_index().unwrap();
    let a_start = a_candidate.started_at();
    let phase_started = tokio::time::Instant::now();
    while phase_started.elapsed() < Duration::from_millis(1500) {
        local_round(nodes, &mut endpoints, &ids, sequence, &LOCAL_FLOWS).await;
        sequence += 1;
        snapshot(nodes, &ids, started, "a-unanswered");
        useful_retained(nodes, &ids, &original);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    network.set_link(ADDRESSES[1], ADDRESSES[7], SimLink::default());
    nodes[1].node.poll_transport_discovery().await;
    let b_candidate = nodes[1].node.peers.connection_values().next().unwrap();
    assert_eq!(
        b_candidate.expected_identity().unwrap().node_addr(),
        ids[7].node_addr()
    );
    let b_link = b_candidate.link_id();
    let b_index = b_candidate.our_index().unwrap();
    let b_start = b_candidate.started_at();
    assert!(
        (1400..2500).contains(&b_start.saturating_sub(a_start)),
        "actual attempt starts must be staggered"
    );
    while nodes[0].node.peers.get_connection(&a_link).is_some() {
        local_round(nodes, &mut endpoints, &ids, sequence, &LOCAL_FLOWS).await;
        sequence += 1;
        snapshot(nodes, &ids, started, "both-unanswered");
        useful_retained(nodes, &ids, &original);
        assert!(
            Node::now_ms() < b_start + TIMEOUT_MS - 500,
            "first timeout must leave a genuine second-owner window"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!nodes[0].node.index_allocator.is_allocated(a_index));
    assert!(!nodes[0].node.links.contains_key(&a_link));
    assert!(nodes[0].node.pending_outbound.is_empty());
    let mut late_original = None;
    for silent in 6..8 {
        let request = nodes[silent]
            .packet_rx
            .try_recv()
            .expect("silent candidate must have received a real Msg1");
        assert!(Msg1Header::parse(request.data.as_slice()).is_some());
        assert_eq!(request.remote_addr, nodes[silent - 6].addr);
        assert_eq!(nodes[silent].node.peer_count(), 0);
        if silent == 7 {
            late_original = Some(request);
        }
    }

    // The bridge remains up from here through teardown. Neither incumbent nor
    // unanswered candidate is removed by the test to manufacture admission.
    network.set_link(ADDRESSES[0], ADDRESSES[1], SimLink::default());
    let hints = nodes[0].node.transports[&nodes[0].transport_id]
        .discover()
        .unwrap();
    assert!(
        hints
            .iter()
            .any(|h| h.pubkey_hint == Some(nodes[1].node.identity().pubkey()))
    );
    nodes[0].node.poll_transport_discovery().await;
    assert_eq!(
        nodes[0]
            .node
            .peers
            .connection_values()
            .next()
            .unwrap()
            .expected_identity()
            .map(|identity| identity.node_addr()),
        Some(ids[1].node_addr())
    );
    let incoming = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = nodes[1].packet_rx.recv().await.unwrap();
            if packet.remote_addr == nodes[0].addr
                && Msg1Header::parse(packet.data.as_slice()).is_some()
            {
                break packet;
            }
            process_dataplane_packet(&mut nodes[1], packet).await;
        }
    })
    .await
    .expect("always-up bridge must deliver its real Msg1");
    let owner = nodes[1].node.peers.get_connection(&b_link).unwrap();
    assert_eq!(owner.our_index(), Some(b_index));
    assert!(!owner.has_session() && owner.is_outbound());
    assert!(owner.idle_time(Node::now_ms()) < TIMEOUT_MS - 300);
    assert!(
        !nodes[1]
            .node
            .peer_has_application_demand(ids[5].node_addr(), Node::now_ms(), 1000)
    );
    assert!(
        Node::now_ms().saturating_sub(
            nodes[1]
                .node
                .get_peer(ids[5].node_addr())
                .unwrap()
                .authenticated_at()
        ) >= 1000
    );
    useful_retained(nodes, &ids, &original);
    snapshot(nodes, &ids, started, "ready-msg1-before-admission");
    process_dataplane_packet(&mut nodes[1], incoming).await;
    snapshot(nodes, &ids, started, "ready-msg1-after-admission");
    let mut progress = false;
    while Node::now_ms() < b_start + TIMEOUT_MS - 150 {
        local_round(nodes, &mut endpoints, &ids, sequence, &LOCAL_FLOWS).await;
        sequence += 1;
        for boundary in &mut nodes[..2] {
            boundary.node.poll_transport_discovery().await;
        }
        snapshot(nodes, &ids, started, "bridge-opportunity");
        useful_retained(nodes, &ids, &original);
        if reciprocal_bridge(nodes, &ids) {
            progress = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if progress {
        assert!(
            Node::now_ms() < b_start + TIMEOUT_MS,
            "original unanswered timeout cannot supply success"
        );
        local_round(nodes, &mut endpoints, &ids, sequence, &[(0, 1), (1, 0)]).await;
        sequence += 1;
        local_round(nodes, &mut endpoints, &ids, sequence, &LOCAL_FLOWS).await;
        useful_retained(nodes, &ids, &original);
        assert!(nodes[1].node.peers.get_connection(&b_link).is_none());
        assert!(!nodes[1].node.index_allocator.is_allocated(b_index));
        late_reply_preserves_bridge(nodes, &ids, late_original.unwrap(), b_index).await;
        sequence += 1;
        local_round(nodes, &mut endpoints, &ids, sequence, &[(0, 1), (1, 0)]).await;
        sequence += 1;
        local_round(nodes, &mut endpoints, &ids, sequence, &LOCAL_FLOWS).await;
        useful_retained(nodes, &ids, &original);
    }
    caps(nodes);
    snapshot(nodes, &ids, started, "final-before-cleanup");
    assert!(
        progress,
        "authenticated ready bridge was starved behind an unanswered outbound until its timeout"
    );
}

fn bridge_owners(
    nodes: &[TestNode],
    ids: &[PeerIdentity],
) -> Vec<(LinkId, Option<SessionIndex>, Option<SessionIndex>, u64)> {
    (0..2)
        .map(|i| {
            let p = nodes[i].node.get_peer(ids[1 - i].node_addr()).unwrap();
            (
                p.link_id(),
                p.our_index(),
                p.their_index(),
                p.session_generation(),
            )
        })
        .collect()
}

async fn late_reply_preserves_bridge(
    nodes: &mut [TestNode],
    ids: &[PeerIdentity],
    original: ReceivedPacket,
    retired: SessionIndex,
) {
    let retained = bridge_owners(nodes, ids);
    assert!(nodes[1].node.get_peer(ids[7].node_addr()).is_none());
    // The previously silent real endpoint now answers the original captured
    // request. No response bytes, session keys, or expiry times are fabricated.
    process_dataplane_packet(&mut nodes[7], original).await;
    let reply = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = nodes[1].packet_rx.recv().await.unwrap();
            if packet.remote_addr == nodes[7].addr
                && Msg2Header::parse(packet.data.as_slice())
                    .is_some_and(|header| header.receiver_idx == retired)
            {
                break packet;
            }
            process_dataplane_packet(&mut nodes[1], packet).await;
        }
    })
    .await
    .expect("late original candidate must return its actual Msg2");
    process_dataplane_packet(&mut nodes[1], reply).await;
    assert_eq!(
        bridge_owners(nodes, ids),
        retained,
        "late original reply must not overwrite the admitted bridge"
    );
    assert!(nodes[1].node.get_peer(ids[7].node_addr()).is_none());
    assert!(!nodes[1].node.index_allocator.is_allocated(retired));
    assert!(
        !nodes[1]
            .node
            .pending_outbound
            .contains_key(&(nodes[1].transport_id, retired.as_u32()))
    );
    caps(nodes);
}
