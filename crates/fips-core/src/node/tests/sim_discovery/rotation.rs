use super::*;
use crate::config::NeighborRotationConfig;
use crate::node::acl::{PeerAclContext, PeerAclReloader};
use spanning_tree::process_available_packets;
use std::time::Instant;

mod carrier_demand;
mod cursor;
mod demand;
mod refresh;
mod unconfirmed;

fn assert_caps(nodes: &[TestNode]) {
    for (index, node) in nodes.iter().enumerate() {
        assert!(node.node.peer_count() <= 1, "peer cap at node {index}");
        assert!(
            node.node.connection_count() <= 1,
            "connection cap at node {index}"
        );
        assert!(
            node.node.link_count() <= if index == 0 { 2 } else { 1 },
            "link cap at node {index}"
        );
    }
}

async fn authenticate(nodes: &mut [TestNode], remote: usize) {
    let local_addr = *nodes[0].node.node_addr();
    let remote_addr = *nodes[remote].node.node_addr();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        process_available_packets(nodes).await;
        assert_caps(nodes);
        if nodes[0].node.get_peer(&remote_addr).is_some()
            && nodes[remote].node.get_peer(&local_addr).is_some()
            && nodes.iter().all(|node| node.node.connection_count() == 0)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "discovered peer did not authenticate"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[tokio::test]
async fn denied_first_discovery_does_not_starve_allowed_rotation() {
    let name = format!("node-sim-rotation-acl-{}", std::process::id());
    let network = SimNetwork::new(27);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    network.set_link("local", "incumbent", SimLink::default());
    register_sim_network(name.clone(), network.clone());
    let mut nodes = vec![
        discovering_node(&name, "local", true).await,
        discovering_node(&name, "incumbent", false).await,
        discovering_node(&name, "candidate-a", false).await,
        discovering_node(&name, "candidate-b", false).await,
    ];
    nodes[0].node.set_max_links(2);
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    nodes[0].node.poll_transport_discovery().await;
    authenticate(&mut nodes, 1).await;
    let incumbent = *nodes[1].node.node_addr();
    let original = {
        let peer = nodes[0].node.get_peer(&incumbent).unwrap();
        (peer.link_id(), peer.our_index(), peer.authenticated_at())
    };
    assert!(nodes.iter().all(|node| node.node.config.peers.is_empty()));

    // Select the denied identity by the actual rotation order, independently
    // of random key generation or transport discovery enumeration order.
    let (denied, allowed) = if nodes[2].node.node_addr() < nodes[3].node.node_addr() {
        (2, 3)
    } else {
        (3, 2)
    };
    let denied_addr = *nodes[denied].node.node_addr();
    let allowed_addr = *nodes[allowed].node.node_addr();
    assert!(
        nodes[0].node.neighbor_rotation_order(denied_addr)
            < nodes[0].node.neighbor_rotation_order(allowed_addr)
    );
    let dir = tempfile::tempdir().unwrap();
    let allow_path = dir.path().join("peers.allow");
    let deny_path = dir.path().join("peers.deny");
    std::fs::write(&deny_path, format!("{}\n", nodes[denied].node.npub())).unwrap();
    nodes[0].node.peer_acl = PeerAclReloader::with_paths(allow_path, deny_path);
    for (index, expected) in [(denied, false), (allowed, true)] {
        let identity = PeerIdentity::from_pubkey_full(nodes[index].node.identity().pubkey_full());
        assert_eq!(
            nodes[0]
                .node
                .authorize_peer(
                    &identity,
                    PeerAclContext::OutboundConnect,
                    nodes[0].transport_id,
                    &nodes[index].addr,
                )
                .is_ok(),
            expected
        );
    }

    // Let the genuine authenticated incumbent reach the configured idle age;
    // no synthetic timestamps, identities, RTT, or admission overrides.
    tokio::time::sleep(Duration::from_millis(1_010)).await;
    assert!(
        nodes[0]
            .node
            .has_neighbor_rotation_opportunity(Node::now_ms())
    );
    network.set_link("local", "candidate-a", SimLink::default());
    network.set_link("local", "candidate-b", SimLink::default());
    let hints = nodes[0].node.transports[&nodes[0].transport_id]
        .discover()
        .unwrap();
    for index in [denied, allowed] {
        assert!(
            hints
                .iter()
                .any(|hint| hint.pubkey_hint == Some(nodes[index].node.identity().pubkey()))
        );
    }

    nodes[0].node.poll_transport_discovery().await;
    assert_eq!(
        nodes[0].node.connection_count(),
        1,
        "a denied lower-ranked identity must not consume the exploration turn"
    );
    let candidate = nodes[0].node.peers.connection_values().next().unwrap();
    assert!(candidate.is_outbound());
    assert_eq!(
        candidate.expected_identity().unwrap().node_addr(),
        &allowed_addr
    );
    assert!(
        !candidate.has_session(),
        "Msg2 has not been dispatched locally"
    );
    assert_eq!(nodes[denied].node.peer_count(), 0);
    assert_eq!(nodes[denied].node.connection_count(), 0);
    assert_caps(&nodes);

    // Dispatch the allowed peer's real Msg1, leaving its authenticated response
    // queued at the full local node. Discovery and Msg1 alone cannot evict.
    let deadline = Instant::now() + Duration::from_secs(2);
    while nodes[allowed].node.peer_count() == 0 {
        process_available_packets(&mut nodes[allowed..=allowed]).await;
        assert!(
            Instant::now() < deadline,
            "allowed candidate did not receive Msg1"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let retained = nodes[0].node.get_peer(&incumbent).unwrap();
    assert_eq!(
        (
            retained.link_id(),
            retained.our_index(),
            retained.authenticated_at()
        ),
        original
    );
    assert!(nodes[0].node.get_peer(&allowed_addr).is_none());
    assert_caps(&nodes);

    authenticate(&mut nodes, allowed).await;
    assert!(nodes[0].node.get_peer(&incumbent).is_none());
    assert!(nodes[0].node.get_peer(&denied_addr).is_none());
    assert_eq!(nodes[0].node.link_count(), 1);
    assert!(nodes[0].node.pending_outbound.is_empty());
    assert_eq!(nodes[denied].node.peer_count(), 0);
    assert_caps(&nodes);
    cleanup_nodes(&mut nodes).await;
    unregister_sim_network(&name);
}
