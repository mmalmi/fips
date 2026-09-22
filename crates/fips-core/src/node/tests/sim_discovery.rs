use super::*;
use crate::config::{SimTransportConfig, TransportInstances};
use crate::{SimLink, SimNetwork, register_sim_network, unregister_sim_network};
use spanning_tree::{TestNode, cleanup_nodes, drain_all_packets};

mod lookup_deadline_cancellation;
mod rotation;

async fn discovering_node(network: &str, addr: &str, auto_connect: bool) -> TestNode {
    let mut config = Config::new();
    config.node.system_files_enabled = false;
    config.node.limits.max_peers = 1;
    config.node.limits.max_connections = 1;
    config.node.limits.max_links = 1;
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network.to_string()),
        addr: Some(addr.to_string()),
        auto_connect: Some(auto_connect),
        ..Default::default()
    });
    configured_discovering_node(config, addr).await
}

async fn configured_discovering_node(config: Config, addr: &str) -> TestNode {
    assert!(config.peers.is_empty());
    let mut node = Node::new(config).unwrap();
    let (packet_tx, packet_rx) = packet_channel(256);
    let (tun_outbound_tx, tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(256);
    node.tun_outbound_rx = Some(tun_outbound_rx);
    let mut transport = node
        .create_transports(&packet_tx)
        .await
        .into_iter()
        .find(|transport| transport.transport_type().name == "sim")
        .expect("configured sim transport");
    let transport_id = transport.transport_id();
    transport.start().await.unwrap();
    node.transports.insert(transport_id, transport);
    TestNode {
        node,
        transport_id,
        packet_rx,
        tun_outbound_tx,
        addr: TransportAddr::from_string(addr),
    }
}

#[tokio::test]
async fn sim_discovery_authenticates_without_roster_and_respects_admission() {
    let name = format!("node-sim-discovery-{}", std::process::id());
    let network = SimNetwork::new(9);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    network.set_link("a", "b", SimLink::default());
    network.set_link("a", "c", SimLink::default());
    register_sim_network(name.clone(), network);
    let mut nodes = vec![
        discovering_node(&name, "a", true).await,
        discovering_node(&name, "b", false).await,
        discovering_node(&name, "c", false).await,
    ];
    let hints = nodes[0].node.transports[&nodes[0].transport_id]
        .discover()
        .unwrap();
    assert_eq!(hints.len(), 2);
    assert_eq!(
        hints[0].pubkey_hint,
        Some(nodes[1].node.identity().pubkey())
    );
    assert!(nodes.iter().all(|node| node.node.peer_count() == 0));

    for node in &mut nodes {
        node.node.poll_transport_discovery().await;
    }
    // Sim is connectionless: discovery starts Noise immediately, without the
    // socket/DNS preparation represented by pending_connects.
    assert!(
        nodes
            .iter()
            .all(|node| node.node.pending_connects.is_empty())
    );
    assert_eq!(nodes[0].node.connection_count(), 1);
    assert!(!nodes[0].node.pending_outbound.is_empty());
    assert_eq!(
        nodes[0]
            .node
            .peers
            .connection_values()
            .next()
            .unwrap()
            .expected_identity()
            .unwrap()
            .node_addr(),
        nodes[1].node.node_addr(),
        "the bounded discovery pass must start only the first neighbor's handshake"
    );
    assert!(nodes.iter().all(|node| node.node.peer_count() == 0));
    assert!(
        nodes[1..]
            .iter()
            .all(|node| node.node.connection_count() == 0 && node.node.pending_outbound.is_empty())
    );
    drain_all_packets(&mut nodes, false).await;
    assert!(nodes[0].node.get_peer(nodes[1].node.node_addr()).is_some());
    assert!(nodes[1].node.get_peer(nodes[0].node.node_addr()).is_some());
    assert_eq!(nodes[2].node.peer_count(), 0);

    nodes[0].node.poll_transport_discovery().await;
    assert!(nodes[0].node.pending_connects.is_empty());
    assert_eq!(nodes[0].node.connection_count(), 0);
    assert!(nodes[0].node.pending_outbound.is_empty());
    assert!(nodes.iter().all(|node| node.node.config.peers.is_empty()
        && node.node.peer_count() <= 1
        && node.node.connection_count() <= 1
        && node.node.link_count() <= 1));
    cleanup_nodes(&mut nodes).await;
    unregister_sim_network(&name);
}
