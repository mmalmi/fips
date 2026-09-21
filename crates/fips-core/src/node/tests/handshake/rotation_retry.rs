//! One discovery retry for an outgoing attempt displaced by reciprocal admission.
use super::*;
use crate::config::SimTransportConfig;
use crate::node::wire::{Msg1Header, build_msg2};
use crate::transport::sim::SimTransport;
use crate::transport::{PacketRx, TransportHandle, packet_channel};
use crate::{SimNetwork, register_sim_network, unregister_sim_network};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    RetryOnce,
    MissingTarget,
    PreparationExpires,
    HandshakeExpires,
}

#[test]
fn transferred_outgoing_gets_one_fresh_discovery_retry_with_original_deadline() {
    run(Case::RetryOnce);
}

#[test]
fn missing_interrupted_target_does_not_block_other_discovery() {
    run(Case::MissingTarget);
}

#[test]
fn retried_hostname_preparation_expires_at_original_deadline() {
    run(Case::PreparationExpires);
}

#[test]
fn retried_noise_expires_at_original_deadline_after_timeout_increase() {
    run(Case::HandshakeExpires);
}

fn run(case: Case) {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-interrupted-retry",
        move || async move {
            let _guard = super::super::super::super::spanning_tree::lock_large_network_test().await;
            let mut node = make_test_node().await;
            let result = AssertUnwindSafe(exercise(&mut node, case))
                .catch_unwind()
                .await;
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        },
    );
}

async fn exercise(node: &mut TestNode, case: Case) {
    let old = make_node();
    let first = make_node();
    let second = make_node();
    let mut target = make_node();
    let mut competitor = make_node();
    // Control the raw cursor's ordering, not the runtime policy or its clocks.
    if target.node_addr() > competitor.node_addr() {
        std::mem::swap(&mut target, &mut competitor);
    }
    let (_old_socket, old_source) = local_path().await;
    let (target_socket, target_source) = local_path().await;
    let (_first_socket, first_source) = local_path().await;
    let (_second_socket, second_source) = local_path().await;
    let mut old_owner = incumbent(node, &old, &old_source, 601, 0).await;
    enable(node, 1);
    node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    node.node.config.node.rate_limit.handshake_timeout_secs = 6;
    node.node.config.node.rekey.enabled = false;
    tokio::time::sleep(Duration::from_millis(1_050)).await;

    let wall_start = tokio::time::Instant::now();
    node.node
        .initiate_connection(node.transport_id, target_source.clone(), identity(&target))
        .await
        .unwrap();
    let original = receive_wire(&target_socket).await;
    let original_header = Msg1Header::parse(&original).expect("actual original Noise Msg1");
    let pending = node.node.peers.connection_values().next().unwrap();
    let original_link = pending.link_id();
    let original_index = pending.our_index().unwrap();
    let original_start = node
        .node
        .neighbor_rotation_started_at(target.node_addr())
        .unwrap();
    let original_cursor = node.node.neighbor_rotation_order(*competitor.node_addr());
    assert!(!original_cursor.0);
    assert_eq!(resources(node), (1, 1, 2, 2));
    // An actual valid reply is retained locally until after the old owner is gone.
    let mut responder = HandshakeState::new_responder(target.identity.keypair());
    responder.set_local_epoch(target.startup_epoch);
    responder
        .read_message_1(original_header.noise_msg1(&original))
        .unwrap();
    let stale_reply = build_msg2(
        SessionIndex::new(602),
        original_header.sender_idx,
        &responder.write_message_2().unwrap(),
    );

    tokio::time::sleep_until(wall_start + Duration::from_millis(1_050)).await;
    let mut first_owner = connect(node, &first, &first_source, 603).await;
    assert_eq!(
        node.node.neighbor_rotation_started_at(first.node_addr()),
        Some(original_start)
    );
    assert!(node.node.get_connection(&original_link).is_none());
    assert!(!node.node.index_allocator.is_allocated(original_index));
    assert_eq!(resources(node), (1, 1, 2, 2));
    assert_eq!(
        node.node.get_peer(old.node_addr()).unwrap().link_id(),
        old_owner.link
    );
    assert_eq!(heartbeat(node, &old, &mut old_owner, 2).await, 2);
    promote(node, &first, &mut first_owner).await;
    assert_eq!(
        node.node.neighbor_rotation_order(*competitor.node_addr()),
        original_cursor
    );

    tokio::time::sleep_until(wall_start + Duration::from_millis(2_150)).await;
    if case == Case::PreparationExpires {
        let port = target_socket.local_addr().unwrap().port();
        node.node
            .initiate_connection(
                node.transport_id,
                TransportAddr::from_string(&format!("localhost:{port}")),
                identity(&target),
            )
            .await
            .unwrap();
        assert_eq!(node.node.pending_connects.len(), 1);
        assert_eq!(node.node.connection_count(), 0);
        assert_eq!(
            node.node.neighbor_rotation_started_at(target.node_addr()),
            Some(original_start),
            "retry must retain the original attempt before DNS is polled"
        );
        // A later configuration increase cannot renew an already owned attempt.
        node.node.config.node.rate_limit.handshake_timeout_secs = 60;
        tokio::time::sleep_until(wall_start + Duration::from_millis(6_100)).await;
        node.node.poll_pending_connects().await;
        assert!(node.node.pending_connects.is_empty());
        assert_eq!(resources(node), (1, 0, 1, 1));
        assert_eq!(heartbeat(node, &first, &mut first_owner, 2).await, 2);
        assert!(
            target_socket.try_recv(&mut [0; 512]).is_err(),
            "expired preparation must not dispatch a fresh Noise request"
        );
        return;
    }

    let mut discovery = Discovery::new(node, &target, &competitor, case).await;
    node.node.poll_transport_discovery().await;
    let expected = if case == Case::MissingTarget {
        &competitor
    } else {
        &target
    };
    let pending = node
        .node
        .peers
        .connection_values()
        .next()
        .expect("fresh discovery dial");
    assert_eq!(
        pending.expected_identity().unwrap().node_addr(),
        expected.node_addr(),
        "the offered interrupted target must get one priority turn, without blocking other candidates"
    );
    assert_eq!(resources(node), (1, 1, 2, 2));
    if case == Case::MissingTarget {
        return;
    }

    let retry_link = pending.link_id();
    let retry_index = pending.our_index().unwrap();
    assert_ne!(retry_link, original_link);
    assert_eq!(pending.last_activity(), original_start);
    assert_eq!(
        node.node.neighbor_rotation_started_at(target.node_addr()),
        Some(original_start)
    );
    assert_eq!(
        node.node.neighbor_rotation_order(*competitor.node_addr()),
        original_cursor
    );
    let retry = tokio::time::timeout(Duration::from_secs(1), discovery.target_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let retry_header = Msg1Header::parse(retry.data.as_slice()).expect("actual fresh retry Msg1");
    assert_ne!(retry_header.sender_idx, original_header.sender_idx);
    assert_ne!(retry.data.as_slice(), original.as_slice());
    assert_eq!(
        pending.source_addr(),
        Some(&TransportAddr::from_string("target")),
        "retry uses the newly discovered carrier, never the incoming source address"
    );
    node.node
        .handle_msg2(packet(node, &target_source, stale_reply))
        .await;
    assert_eq!(
        node.node.get_connection(&retry_link).unwrap().our_index(),
        Some(retry_index)
    );
    assert!(node.node.get_peer(target.node_addr()).is_none());

    if case == Case::HandshakeExpires {
        node.node.config.node.rate_limit.handshake_timeout_secs = 60;
        tokio::time::sleep_until(wall_start + Duration::from_millis(6_100)).await;
        node.node.check_timeouts().await;
        assert_eq!(resources(node), (1, 0, 1, 1));
        assert!(!node.node.index_allocator.is_allocated(retry_index));
        assert!(node.node.pending_outbound.is_empty());
        assert_eq!(heartbeat(node, &first, &mut first_owner, 2).await, 2);
        return;
    }

    tokio::time::sleep_until(wall_start + Duration::from_millis(3_250)).await;
    let mut second_owner = connect(node, &second, &second_source, 604).await;
    assert!(node.node.get_connection(&retry_link).is_none());
    assert!(!node.node.index_allocator.is_allocated(retry_index));
    assert_eq!(
        node.node.neighbor_rotation_started_at(second.node_addr()),
        Some(original_start)
    );
    assert_eq!(
        node.node
            .get_connection(&second_owner.link)
            .unwrap()
            .last_activity(),
        original_start
    );
    promote(node, &second, &mut second_owner).await;
    tokio::time::sleep_until(wall_start + Duration::from_millis(4_350)).await;
    node.node.poll_transport_discovery().await;
    let next = node.node.peers.connection_values().next().unwrap();
    assert_eq!(
        next.expected_identity().unwrap().node_addr(),
        competitor.node_addr(),
        "a second transfer must not re-arm the consumed preference"
    );
    assert_eq!(resources(node), (1, 1, 2, 2));
    assert_eq!(heartbeat(node, &second, &mut second_owner, 2).await, 2);
}

fn identity(node: &Node) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(node.identity.pubkey_full())
}

async fn receive_wire(socket: &tokio::net::UdpSocket) -> Vec<u8> {
    let mut wire = vec![0; 512];
    let length = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut wire))
        .await
        .unwrap()
        .unwrap();
    wire.truncate(length);
    wire
}

async fn promote(node: &mut TestNode, remote: &Node, candidate: &mut Candidate) {
    let proof = candidate.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    assert!(node.node.confirm_pending_handshake(proof).await);
    assert_eq!(await_heartbeat(node, remote, 1).await, 1);
    assert_eq!(resources(node), (1, 0, 1, 1));
}

struct Discovery {
    name: String,
    _target: SimTransport,
    _competitor: SimTransport,
    _source_rx: PacketRx,
    target_rx: PacketRx,
    _competitor_rx: PacketRx,
}

impl Discovery {
    async fn new(node: &mut TestNode, target: &Node, competitor: &Node, case: Case) -> Self {
        let name = format!("rotation-retry-{}-{case:?}", std::process::id());
        let network = SimNetwork::new(191);
        register_sim_network(name.clone(), network.clone());
        let (source, source_rx) = sim(&name, "source", &node.node, true).await;
        let (target_transport, target_rx) = sim(&name, "target", target, false).await;
        let (competitor_transport, competitor_rx) =
            sim(&name, "competitor", competitor, false).await;
        if case == Case::MissingTarget {
            network.set_link_up("source", "target", false);
        }
        node.node
            .transports
            .insert(TransportId::new(2), TransportHandle::Sim(source));
        Self {
            name,
            _target: target_transport,
            _competitor: competitor_transport,
            _source_rx: source_rx,
            target_rx,
            _competitor_rx: competitor_rx,
        }
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        unregister_sim_network(&self.name);
    }
}

async fn sim(
    network: &str,
    address: &str,
    node: &Node,
    automatic: bool,
) -> (SimTransport, PacketRx) {
    let (tx, rx) = packet_channel(16);
    let mut transport = SimTransport::new(
        TransportId::new(2),
        None,
        SimTransportConfig {
            network: Some(network.to_owned()),
            addr: Some(address.to_owned()),
            auto_connect: Some(automatic),
            ..Default::default()
        },
        tx,
    );
    transport.set_local_pubkey(node.identity.pubkey());
    transport.start_async().await.unwrap();
    (transport, rx)
}
