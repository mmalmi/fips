use super::*;
use crate::config::SimTransportConfig;
use crate::transport::sim::SimTransport;
use crate::transport::{PacketRx, TransportHandle, packet_channel};
use crate::{SimNetwork, register_sim_network, unregister_sim_network};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Turn {
    Expires,
    EmptyScan,
    NoSource,
}

#[test]
fn inbound_rotation_reserves_a_finite_local_discovery_turn() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-finite-direction-preference",
        || exercise(Turn::Expires),
    );
}

#[test]
fn empty_automatic_discovery_releases_inbound_rotation_preference() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-empty-discovery-turn",
        || exercise(Turn::EmptyScan),
    );
}

#[test]
fn inbound_rotation_without_automatic_discovery_uses_only_normal_cooldown() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-no-discovery-source",
        || exercise(Turn::NoSource),
    );
}

async fn exercise(mode: Turn) {
    let mut node = make_test_node().await;
    let _discovery = if mode != Turn::NoSource {
        Some(add_empty_automatic_discovery(&mut node, mode).await)
    } else {
        assert!(
            node.node
                .transports
                .values()
                .all(|transport| !transport.auto_connect())
        );
        None
    };
    let old = make_node();
    let first = make_node();
    let next = make_node();
    let (_old_socket, old_source) = local_path().await;
    let (first_socket, first_source) = local_path().await;
    let (next_socket, next_source) = local_path().await;
    let old_owner = incumbent(&mut node, &old, &old_source, 170, 0).await;
    enable(&mut node, 1);
    node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    node.node.config.node.rate_limit.handshake_timeout_secs = 2;
    node.node.config.node.rekey.enabled = false;
    // Age the real authenticated incumbent; do not inject timestamps
    // or write the preference/rotation bookkeeping from the test.
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    assert!(node.node.has_neighbor_rotation_opportunity(Node::now_ms()));

    let mut first_owner = connect(&mut node, &first, &first_source, 171).await;
    assert_actual_response(&node, &first_owner, &first_socket).await;
    assert_eq!(resources(&node), (1, 1, 2, 2));
    assert_eq!(
        node.node.get_peer(old.node_addr()).unwrap().link_id(),
        old_owner.link
    );
    let proof = first_owner.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    assert!(node.node.confirm_pending_handshake(proof).await);
    let promoted_at = tokio::time::Instant::now();
    process_available_packets(std::slice::from_mut(&mut node)).await;
    assert_eq!(await_heartbeat(&mut node, &first, 1).await, 1);
    assert_eq!(resources(&node), (1, 0, 1, 1));
    assert!(node.node.get_peer(old.node_addr()).is_none());
    assert!(!node.node.index_allocator.is_allocated(old_owner.index));
    let active = node.node.get_peer(first.node_addr()).unwrap();
    let original_owner = (
        active.link_id(),
        active.our_index(),
        active.their_index(),
        active.session_generation(),
        active.remote_epoch(),
    );
    let ordering = node.node.neighbor_rotation_order(*next.node_addr());

    tokio::time::sleep_until(promoted_at + Duration::from_millis(1_100)).await;
    // The normal cooldown and minimum age have both elapsed. A local
    // discovery attempt is genuinely eligible; its finite preference
    // is the only reason a new incoming identity should be refused.
    assert!(node.node.has_neighbor_rotation_opportunity(Node::now_ms()));
    assert!(
        node.node
            .can_attempt_neighbor_rotation(next.node_addr(), true, Node::now_ms())
    );
    assert!(promoted_at.elapsed() < Duration::from_millis(2_900));
    if mode != Turn::NoSource {
        let _unanswered = request(&mut node, &next, &next_source, 172).await;
        assert_eq!(
            resources(&node),
            (1, 0, 1, 1),
            "a fresh incoming attempt after cooldown must leave local discovery its bounded turn"
        );
        assert!(node.node.get_peer(next.node_addr()).is_none());
        assert_eq!(
            node.node.neighbor_rotation_order(*next.node_addr()),
            ordering
        );
        let active = node.node.get_peer(first.node_addr()).unwrap();
        assert_eq!(
            (
                active.link_id(),
                active.our_index(),
                active.their_index(),
                active.session_generation(),
                active.remote_epoch()
            ),
            original_owner,
            "denied incoming traffic must not change the incumbent's real key ownership"
        );
        let mut response = [0; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), next_socket.recv(&mut response))
                .await
                .is_err(),
            "denied fresh incoming must not advertise Msg2"
        );
        assert_eq!(heartbeat(&mut node, &first, &mut first_owner, 2).await, 2);

        match mode {
            Turn::Expires => {
                // No discovery poll runs. The finite fallback must still
                // restore incoming admission on an incoming-only encounter.
                tokio::time::sleep_until(promoted_at + Duration::from_millis(3_100)).await;
            }
            Turn::EmptyScan => {
                // The operational Sim source has no other registered endpoint.
                // Exercise the actual eligible poll with a spare handshake/link
                // slot; an empty result must release the preference early.
                assert!(node.node.has_neighbor_rotation_opportunity(Node::now_ms()));
                node.node.poll_transport_discovery().await;
                assert_eq!(resources(&node), (1, 0, 1, 1));
                assert!(promoted_at.elapsed() < Duration::from_millis(2_900));
            }
            Turn::NoSource => unreachable!(),
        }
    }
    // Without any automatic source, normal cooldown alone suffices. All
    // modes must leave the incumbent intact until this fresh proof succeeds.
    let mut next_owner = connect(&mut node, &next, &next_source, 173).await;
    assert_actual_response(&node, &next_owner, &next_socket).await;
    assert_eq!(resources(&node), (1, 1, 2, 2));
    assert_eq!(
        node.node.get_peer(first.node_addr()).unwrap().link_id(),
        first_owner.link
    );
    assert!(node.node.get_peer(next.node_addr()).is_none());
    let proof = next_owner.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    assert!(node.node.confirm_pending_handshake(proof).await);
    process_available_packets(std::slice::from_mut(&mut node)).await;
    assert_eq!(await_heartbeat(&mut node, &next, 1).await, 1);
    assert_eq!(resources(&node), (1, 0, 1, 1));
    assert!(node.node.get_peer(first.node_addr()).is_none());
    assert!(!node.node.index_allocator.is_allocated(first_owner.index));
    let active = node.node.get_peer(next.node_addr()).unwrap();
    assert_eq!(active.link_id(), next_owner.link);
    assert_eq!(active.our_index(), Some(next_owner.index));
    assert_eq!(active.remote_epoch(), Some(next.startup_epoch));
    assert_eq!(heartbeat(&mut node, &next, &mut next_owner, 2).await, 2);
    cleanup_nodes(std::slice::from_mut(&mut node)).await;
}

async fn assert_actual_response(
    node: &TestNode,
    candidate: &Candidate,
    socket: &tokio::net::UdpSocket,
) {
    let mut response = [0; 512];
    let length = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut response))
        .await
        .expect("eligible incoming candidate receives the actual retained Msg2")
        .unwrap();
    assert_eq!(
        &response[..length],
        node.node
            .get_connection(&candidate.link)
            .unwrap()
            .handshake_msg2()
            .unwrap()
    );
}

/// The real registered transport is deliberately the network's sole endpoint,
/// so normal discover() returns an empty inventory without a mocked policy.
struct RegisteredNetwork(String);

impl Drop for RegisteredNetwork {
    fn drop(&mut self) {
        unregister_sim_network(&self.0);
    }
}

async fn add_empty_automatic_discovery(
    node: &mut TestNode,
    mode: Turn,
) -> (RegisteredNetwork, PacketRx) {
    let name = format!("rotation-direction-{}-{mode:?}", std::process::id());
    let network = SimNetwork::new(193);
    register_sim_network(name.clone(), network);
    let registered = RegisteredNetwork(name.clone());
    let (tx, rx) = packet_channel(8);
    let id = TransportId::new(2);
    assert!(!node.node.transports.contains_key(&id));
    let mut transport = SimTransport::new(
        id,
        None,
        SimTransportConfig {
            network: Some(name),
            addr: Some("local".into()),
            auto_connect: Some(true),
            ..Default::default()
        },
        tx,
    );
    transport.set_local_pubkey(node.node.identity.pubkey());
    transport.start_async().await.unwrap();
    let transport = TransportHandle::Sim(transport);
    assert!(transport.is_operational() && transport.auto_connect());
    assert!(transport.discover().unwrap().is_empty());
    node.node.transports.insert(id, transport);
    (registered, rx)
}
