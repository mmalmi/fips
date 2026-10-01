//! Discovery preferences use only the topology advertised by the owning Node.
use super::*;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

async fn turn(nodes: &mut [TestNode]) {
    for node in nodes.iter_mut() {
        node.node.resend_pending_handshakes(Node::now_ms()).await;
        node.node.check_tree_state().await;
        node.node.send_pending_tree_announces().await;
    }
    poll_available_packets(nodes).await;
}

#[test]
fn a_different_connected_tree_precedes_an_isolated_ordinary_candidate() {
    run(false);
}

#[test]
fn repeated_topology_hints_cannot_renew_an_attempt_or_skip_ordinary_service() {
    run(true);
}

fn run(expire: bool) {
    run_large_stack_async_test("rotation-topology", move || async move {
        let _guard = spanning_tree::lock_large_network_test().await;
        let name = format!("rotation-topology-{expire}-{}", std::process::id());
        let network = SimNetwork::new(111);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for address in ["local", "old", "candidate-a", "candidate-b", "partner"] {
            let mut node = discovering_node(&name, address, true).await;
            node.node.max_peers = 2;
            node.node.max_links = 3;
            node.node.config.node.rekey.enabled = false;
            nodes.push(node);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, &network, expire))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, expire: bool) {
    // Existing identities determine roles; no key search or synthetic tree state.
    nodes[2..].sort_by_key(|node| *node.node.node_addr());
    nodes[2..].rotate_left(1);
    nodes[0].node.max_peers = 1;
    nodes[0].node.max_links = 2;
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    nodes[0].node.config.node.rate_limit.handshake_timeout_secs = 6;
    network.set_link(
        nodes[0].addr.as_str().unwrap(),
        nodes[1].addr.as_str().unwrap(),
        SimLink::default(),
    );
    nodes[0].node.poll_transport_discovery().await;
    drain_all_packets(nodes, false).await;
    assert_eq!(nodes[0].node.peer_count(), 1);
    let (local, rest) = nodes.split_at_mut(2);
    rest[..2].sort_by_key(|node| {
        local[0]
            .node
            .neighbor_rotation_order(*node.node.node_addr())
    });
    let ids: Vec<_> = nodes.iter().map(|n| *n.node.node_addr()).collect();
    assert!(
        nodes[0].node.neighbor_rotation_order(ids[2])
            < nodes[0].node.neighbor_rotation_order(ids[3])
    );
    let original = nodes[0].node.get_peer(&ids[1]).unwrap();
    let owner = (
        original.link_id(),
        original.our_index(),
        original.authenticated_at(),
    );

    // Merely exposing the advertiser does not manufacture a component hint.
    network.set_link(
        nodes[0].addr.as_str().unwrap(),
        nodes[3].addr.as_str().unwrap(),
        SimLink::default(),
    );
    let hints = nodes[0].node.transports[&nodes[0].transport_id]
        .discover()
        .unwrap();
    assert_eq!(
        hints
            .iter()
            .find(|p| p.pubkey_hint == Some(nodes[3].node.identity.pubkey()))
            .unwrap()
            .connected_root_hint,
        None
    );
    network.set_link(
        nodes[0].addr.as_str().unwrap(),
        nodes[3].addr.as_str().unwrap(),
        SimLink {
            up: false,
            ..Default::default()
        },
    );
    network.set_link(
        nodes[3].addr.as_str().unwrap(),
        nodes[4].addr.as_str().unwrap(),
        SimLink::default(),
    );
    nodes[3].node.poll_transport_discovery().await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            turn(nodes).await;
            if nodes[3].node.get_peer(&ids[4]).is_some()
                && nodes[4].node.get_peer(&ids[3]).is_some()
                && *nodes[3].node.tree_state().root() == ids[4]
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ordinary authentication and TreeAnnounce must form the remote tree");
    // Publication is through normal Node polling, never by the Sim network
    // inferring components or the test assigning advertised root values.
    for node in nodes.iter_mut() {
        node.node.poll_transport_discovery().await;
    }
    for candidate in [2, 3] {
        network.set_link(
            nodes[0].addr.as_str().unwrap(),
            nodes[candidate].addr.as_str().unwrap(),
            SimLink::default(),
        );
    }
    let hints = nodes[0].node.transports[&nodes[0].transport_id]
        .discover()
        .unwrap();
    for (candidate, expected) in [(2, None), (3, Some(ids[4]))] {
        let hint = hints
            .iter()
            .find(|p| p.pubkey_hint == Some(nodes[candidate].node.identity.pubkey()))
            .unwrap();
        assert_eq!(hint.connected_root_hint, expected);
    }
    assert_ne!(*nodes[0].node.tree_state().root(), ids[4]);
    while Node::now_ms().saturating_sub(owner.2) < 1_050 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let ordinary_order = [2, 3].map(|i| nodes[0].node.neighbor_rotation_order(ids[i]));
    nodes[0].node.poll_transport_discovery().await;
    let candidate = nodes[0].node.peers.connection_values().next().unwrap();
    assert_eq!(
        candidate.expected_identity().unwrap().node_addr(),
        &ids[3],
        "the connected foreign tree must win this preferred turn"
    );
    assert!(!candidate.has_session());
    let kept = nodes[0].node.get_peer(&ids[1]).unwrap();
    assert_eq!(
        (kept.link_id(), kept.our_index(), kept.authenticated_at()),
        owner
    );
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[0].node.connection_count(), 1);
    assert_eq!(nodes[0].node.link_count(), 2);
    assert_eq!(nodes[0].node.index_allocator.count(), 2);
    assert_eq!(
        [2, 3].map(|i| nodes[0].node.neighbor_rotation_order(ids[i])),
        ordinary_order,
        "a preferred attempt must leave the ordinary cursor intact"
    );
    let target = if expire {
        // Keep the real connected advertiser visible but deliberately do not
        // dispatch its packets. Repeated hints cannot renew the frozen attempt.
        let deadline = nodes[0].node.neighbor_rotation_deadline(&ids[3]).unwrap();
        while Node::now_ms().saturating_add(100) < deadline {
            nodes[0]
                .node
                .resend_pending_handshakes(Node::now_ms())
                .await;
            nodes[0].node.check_timeouts().await;
            nodes[0].node.poll_transport_discovery().await;
            assert_eq!(
                nodes[0].node.neighbor_rotation_deadline(&ids[3]),
                Some(deadline)
            );
            assert_eq!(nodes[0].node.connection_count(), 1);
            assert_eq!(nodes[0].node.link_count(), 2);
            assert_eq!(nodes[0].node.index_allocator.count(), 2);
            let held = nodes[0].node.get_peer(&ids[1]).unwrap();
            assert_eq!(
                (held.link_id(), held.our_index(), held.authenticated_at()),
                owner
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(
            deadline.saturating_sub(Node::now_ms()).saturating_add(25),
        ))
        .await;
        nodes[0].node.check_timeouts().await;
        assert_eq!(nodes[0].node.connection_count(), 0);
        assert_eq!(nodes[0].node.link_count(), 1);
        assert_eq!(nodes[0].node.index_allocator.count(), 1);
        nodes[0].node.poll_transport_discovery().await;
        let candidate = nodes[0].node.peers.connection_values().next().unwrap();
        assert_eq!(
            candidate.expected_identity().unwrap().node_addr(),
            &ids[2],
            "the still-advertised foreign tree cannot take the owed ordinary turn"
        );
        assert!(!candidate.has_session());
        2
    } else {
        3
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if expire {
                turn(&mut nodes[..3]).await;
            } else {
                turn(nodes).await;
            }
            if nodes[0].node.get_peer(&ids[target]).is_some()
                && nodes[target].node.get_peer(&ids[0]).is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the preference must still finish native authentication");
    let mut endpoint = nodes[target].node.attach_endpoint_data_io(8).unwrap();
    let identity = PeerIdentity::from_pubkey_full(nodes[target].node.identity.pubkey_full());
    let payload = b"payload after topology discovery and actual Noise".to_vec();
    send_endpoint_data_via_dataplane(&mut nodes[0].node, identity, payload.clone())
        .await
        .unwrap();
    let event = recv_endpoint_event_while_draining(
        nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(2),
        "topology-selected payload",
    )
    .await;
    endpoint.event_rx.release_messages(event.messages.len());
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        payload
    );
}
