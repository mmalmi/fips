//! Real queued destinations compete with ordinary discovered identities.
use super::*;
use crate::node::EndpointDataIo;
use crate::node::tests::session::{
    build_ipv6_packet, run_large_stack_async_test, send_endpoint_data_via_dataplane,
    send_tun_packet_via_dataplane,
};
use crate::node::wire::Msg1Header;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const ADDRESSES: [&str; 5] = [
    "local",
    "incumbent",
    "candidate-a",
    "candidate-b",
    "candidate-c",
];
const PAYLOAD: &[u8] = b"one original queued direct destination payload";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Endpoint,
    Tun,
    Fairness,
    Measurement,
}

#[test]
fn queued_endpoint_destination_precedes_earlier_discovered_candidates() {
    run(Case::Endpoint);
}

#[test]
fn queued_tun_destination_precedes_earlier_discovered_candidates() {
    run(Case::Tun);
}

#[test]
fn unresponsive_demand_alternates_with_advancing_cursor_attempts() {
    run(Case::Fairness);
}

#[test]
fn measure_original_queued_delivery_with_up_to_three_candidate_admissions() {
    run(Case::Measurement);
}

fn run(case: Case) {
    run_large_stack_async_test("rotation-queued-demand", move || async move {
        let _guard = spanning_tree::lock_large_network_test().await;
        let name = format!("rotation-queued-demand-{}-{case:?}", std::process::id());
        let network = SimNetwork::new(97);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for (i, address) in ADDRESSES.iter().enumerate() {
            nodes.push(discovering_node(&name, address, i == 0).await);
        }
        // Keep the still-advertising incumbent before B/C/D in real identity
        // order. Its later rediscovery must not change the measured cohort.
        nodes[1..].sort_by_key(|node| *node.node.node_addr());
        network.set_link(
            ADDRESSES[0],
            nodes[1].addr.as_str().unwrap(),
            SimLink::default(),
        );
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

fn queued(node: &Node, destination: &NodeAddr, tun: bool) -> usize {
    if tun {
        node.pending_session_traffic
            .tun_packets_for(destination)
            .map_or(0, |q| q.len())
    } else {
        node.pending_session_traffic
            .endpoint_data_for(destination)
            .map_or(0, |q| q.len())
    }
}

fn assert_inventory(nodes: &[TestNode]) {
    assert_caps(nodes);
    assert!(nodes.iter().all(|n| n.node.config.peers.is_empty()));
    assert!(nodes.iter().all(|n| n.node.pending_connects.is_empty()));
}

/// Drive ordinary maintenance and completion. The fairness case deliberately
/// leaves candidate handlers unresponsive; their real Sim endpoints still
/// advertise and receive the actual Noise flights.
async fn turn(nodes: &mut [TestNode], responsive: bool, tick: &mut Instant) {
    let live = if responsive { nodes.len() } else { 2 };
    if Instant::now() >= *tick {
        *tick = Instant::now() + Duration::from_secs(1);
        for node in &mut nodes[..live] {
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
    process_available_packets(&mut nodes[..live]).await;
    assert_inventory(nodes);
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, case: Case) {
    nodes[0].node.set_max_links(2);
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    nodes[0].node.config.node.rate_limit.handshake_timeout_secs = 3;
    nodes[0].node.poll_transport_discovery().await;
    authenticate(nodes, 1).await;
    let mut order = [2, 3, 4];
    order.sort_by_key(|&i| {
        nodes[0]
            .node
            .neighbor_rotation_order(*nodes[i].node.node_addr())
    });
    let [b, c, d] = order;
    let remote = PeerIdentity::from_pubkey_full(nodes[d].node.identity().pubkey_full());
    let destination = *remote.node_addr();
    let source = *nodes[0].node.node_addr();
    let incumbent = *nodes[1].node.node_addr();
    let original = nodes[0].node.get_peer(&incumbent).unwrap().link_id();
    let authenticated = nodes[0]
        .node
        .get_peer(&incumbent)
        .unwrap()
        .authenticated_at();
    let mut tick = Instant::now();
    while Node::now_ms().saturating_sub(authenticated) < 1_050 {
        turn(nodes, true, &mut tick).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        nodes[0]
            .node
            .has_neighbor_rotation_opportunity(Node::now_ms())
    );
    let _source_endpoint = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut receiver = nodes[d].node.attach_endpoint_data_io(8).unwrap();
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[d].node.tun_tx = Some(tun_tx);
    let tun = case == Case::Tun;
    let original_payload = if tun {
        // A locally addressed TUN destination needs its public key to resolve
        // the IPv6 prefix. This installs identity knowledge only: no peer,
        // coordinates, selected route, session or synthetic admission.
        nodes[0]
            .node
            .register_identity(destination, remote.pubkey_full());
        build_ipv6_packet(
            &crate::FipsAddress::from_node_addr(&source),
            &crate::FipsAddress::from_node_addr(&destination),
            PAYLOAD,
        )
    } else {
        PAYLOAD.to_vec()
    };
    assert!(nodes[0].node.get_peer(&destination).is_none());
    assert!(nodes[0].node.get_session(&destination).is_none());
    let offered = Instant::now();
    if tun {
        send_tun_packet_via_dataplane(nodes, 0, original_payload.clone()).await;
    } else {
        send_endpoint_data_via_dataplane(&mut nodes[0].node, remote, original_payload.clone())
            .await
            .unwrap();
    }
    assert_eq!(
        queued(&nodes[0].node, &destination, tun),
        1,
        "the real original must be locally queued before discovery"
    );
    for candidate in &nodes[2..] {
        network.set_link(
            ADDRESSES[0],
            candidate.addr.as_str().unwrap(),
            SimLink::default(),
        );
    }
    let cursor = nodes[0]
        .node
        .neighbor_rotation_order(*nodes[b].node.node_addr());
    if case == Case::Fairness {
        fairness(nodes, order, original, offered, &mut tick).await;
        return;
    }
    nodes[0].node.poll_transport_discovery().await;
    let selected = current_attempt(nodes);
    if case != Case::Measurement {
        assert_eq!(
            selected.0, destination,
            "queued D must precede both earlier ordinary discovered candidates"
        );
        assert_eq!(
            nodes[0]
                .node
                .neighbor_rotation_order(*nodes[b].node.node_addr()),
            cursor,
            "demand preference must not move the ordinary exploration cursor"
        );
    }
    let mut attempts = vec![selected.0];
    let mut last_attempt = selected.1;
    let mut last_incumbent = incumbent;
    let mut admissions = 0;
    let mut next_discovery = Instant::now() + Duration::from_secs(1);
    let deadline = offered + Duration::from_secs(15);
    let delivered_at = loop {
        turn(nodes, true, &mut tick).await;
        if let Some(peer) = nodes[0].node.peers.values().next()
            && *peer.node_addr() != last_incumbent
        {
            admissions += 1;
            last_incumbent = *peer.node_addr();
            assert!(
                admissions <= 3,
                "at most three ordinary candidate admissions"
            );
        }
        if receive(&mut receiver, &tun_rx, tun, &source, &original_payload) {
            break Instant::now();
        }
        assert!(
            Instant::now() < deadline,
            "original queued payload delivery deadline"
        );
        if Instant::now() >= next_discovery {
            next_discovery = Instant::now() + Duration::from_secs(1);
            nodes[0].node.poll_transport_discovery().await;
            if nodes[0].node.connection_count() > 0 {
                let selected = current_attempt(nodes);
                if selected.1 != last_attempt {
                    attempts.push(selected.0);
                    last_attempt = selected.1;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert!(nodes[0].node.get_peer(&destination).is_some());
    assert!(nodes[d].node.get_peer(&source).is_some());
    assert_eq!(queued(&nodes[0].node, &destination, tun), 0);
    let duplicate_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < duplicate_deadline {
        turn(nodes, true, &mut tick).await;
        assert!(
            !receive(&mut receiver, &tun_rx, tun, &source, &original_payload),
            "the original one-shot payload must not be duplicated"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let labels: Vec<_> = attempts
        .iter()
        .map(|target| {
            if *target == destination {
                "D"
            } else if *target == *nodes[b].node.node_addr() {
                "B"
            } else if *target == *nodes[c].node.node_addr() {
                "C"
            } else {
                "other"
            }
        })
        .collect();
    eprintln!(
        "queued discovery delivery: {}",
        serde_json::json!({"case":format!("{case:?}"),
        "attempts":labels,"admissions":admissions,"offered":1,"delivered":1,
        "first_observed_ms":delivered_at.duration_since(offered).as_millis(),
        "duplicate_observation_ms":200})
    );
    assert_inventory(nodes);
}

fn current_attempt(nodes: &[TestNode]) -> (NodeAddr, LinkId) {
    assert_eq!(nodes[0].node.connection_count(), 1);
    let conn = nodes[0].node.peers.connection_values().next().unwrap();
    assert!(conn.is_outbound());
    (
        *conn.expected_identity().unwrap().node_addr(),
        conn.link_id(),
    )
}

fn receive(
    receiver: &mut EndpointDataIo,
    tun_rx: &crate::upper::tun::TunRx,
    tun: bool,
    source: &NodeAddr,
    expected: &[u8],
) -> bool {
    if tun {
        match tun_rx.try_recv_packet() {
            Ok(packet) => {
                assert_eq!(packet.as_slice(), expected);
                true
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => false,
            Err(error) => panic!("TUN receiver closed: {error}"),
        }
    } else {
        match receiver.event_rx.try_recv() {
            Ok(event) => {
                let count = event.message_count();
                assert_eq!(count, 1, "exactly the one original endpoint payload");
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
}

async fn fairness(
    nodes: &mut [TestNode],
    order: [usize; 3],
    original: LinkId,
    offered: Instant,
    tick: &mut Instant,
) {
    let [b, c, d] = order;
    let target = *nodes[d].node.node_addr();
    let incumbent = *nodes[1].node.node_addr();
    let mut attempts = Vec::new();
    for (position, expected) in [d, b, d, c].into_iter().enumerate() {
        assert_eq!(queued(&nodes[0].node, &target, false), 1);
        let cursor_before: Vec<_> = order
            .iter()
            .map(|&i| {
                nodes[0]
                    .node
                    .neighbor_rotation_order(*nodes[i].node.node_addr())
            })
            .collect();
        nodes[0].node.poll_transport_discovery().await;
        let (chosen, link) = current_attempt(nodes);
        assert_eq!(
            chosen,
            *nodes[expected].node.node_addr(),
            "persistent unresponsive demand must alternate D, B, D, C"
        );
        let cursor_after: Vec<_> = order
            .iter()
            .map(|&i| {
                nodes[0]
                    .node
                    .neighbor_rotation_order(*nodes[i].node.node_addr())
            })
            .collect();
        if expected == d {
            assert_eq!(
                cursor_after, cursor_before,
                "demand does not rewind the cursor"
            );
        } else {
            assert_ne!(
                cursor_after, cursor_before,
                "ordinary attempt advances the cursor"
            );
        }
        let conn = nodes[0].node.get_connection(&link).unwrap();
        let index = conn.our_index().unwrap();
        let deadline = nodes[0].node.neighbor_rotation_deadline(&chosen).unwrap();
        let flight_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let packet =
                tokio::time::timeout_at(flight_deadline.into(), nodes[expected].packet_rx.recv())
                    .await
                    .expect("real candidate Msg1 arrival")
                    .unwrap();
            if Msg1Header::parse(packet.data.as_slice())
                .is_some_and(|header| header.sender_idx == index)
            {
                assert_eq!(packet.remote_addr, nodes[0].addr);
                break;
            }
        }
        attempts.push(if expected == d {
            "D"
        } else if expected == b {
            "B"
        } else {
            "C"
        });
        if position == 3 {
            break;
        }
        let cleanup_deadline = Instant::now() + Duration::from_secs(5);
        while nodes[0].node.get_connection(&link).is_some() {
            assert_eq!(
                nodes[0].node.neighbor_rotation_deadline(&chosen),
                Some(deadline)
            );
            assert!(
                Instant::now() < cleanup_deadline,
                "ordinary original attempt expiry"
            );
            turn(nodes, false, tick).await;
            assert_eq!(
                nodes[0].node.get_peer(&incumbent).unwrap().link_id(),
                original
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(Node::now_ms() >= deadline, "no synthetic early retirement");
        assert!(!nodes[0].node.index_allocator.is_allocated(index));
        assert!(nodes[0].node.pending_outbound.is_empty());
    }
    assert_inventory(nodes);
    eprintln!(
        "queued discovery fairness: {}",
        serde_json::json!({"attempts":attempts,
        "promotions":0,"queued_original":1,"elapsed_ms":offered.elapsed().as_millis()})
    );
}
